from pathlib import Path

import pytest

from ablation.analyzers.c166_execution import (
    C166CANController,
    C166CANMessage,
    C166CPU,
    C166ExecutionError,
    C166Memory,
)
from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder


A1396 = Path('/media/cowboy/research/CERN/analysis/edms-firmware/a1396.bin')


def machine(words: dict[int, str], *, size: int = 0x60, dpp_pages=None):
    image = bytearray(size)
    for address, raw in words.items():
        data = bytes.fromhex(raw)
        offset = address - 0x20000
        image[offset:offset + len(data)] = data
    decoder = EcuC166Decoder(bytes(image), 0x20000)
    memory = C166Memory(bytes(image), 0x20000, dpp_pages=dpp_pages)
    return decoder, memory


def test_arithmetic_loop_flags_and_srst():
    decoder, memory = machine({
        0x20000: 'e148',
        0x20002: '2981',
        0x20004: '3dfe',
        0x20006: 'f7f8fe84',
        0x2000A: 'b748b7b7',
    })
    cpu = C166CPU(decoder, memory)

    result = cpu.run()

    assert result.reason == 'srst'
    assert result.steps == 11
    assert result.pc == 0x2000A
    assert memory.read(0x84FE) == b'\x00'
    assert result.registers[4] == 0
    assert result.trace[-1].raw == bytes.fromhex('b748b7b7')


def test_calls_return_to_modeled_stack():
    decoder, memory = machine({
        0x20000: 'da020c00',
        0x20004: 'f7f8fe84',
        0x20008: 'b748b7b7',
        0x2000C: 'db00',
    })

    result = C166CPU(decoder, memory).run()

    assert result.reason == 'srst'
    assert result.pc == 0x20008
    assert result.steps == 4


def test_dpp_mapped_indirect_read_preserves_original_address():
    decoder, memory = machine({
        0x20000: 'f4a6ae5a',
        0x20004: 'f7fafe84',
        0x20008: 'b748b7b7',
    }, dpp_pages={1: 7})
    memory.write(0x1DAAE, b'Z')

    result = C166CPU(decoder, memory).run()

    assert result.reason == 'srst'
    assert memory.read(0x84FE) == b'Z'
    assert result.registers[6] == 0


def test_protected_spans_reject_firmware_write_but_allow_ram():
    memory = C166Memory(
        b'\xcb\x00',
        0x20000,
        protected_ranges=((0x20000, 0x20002),),
    )
    memory.write(0x84FE, b'\x01')
    with pytest.raises(C166ExecutionError, match='protected firmware'):
        memory.write(0x20000, b'\x00')
    with pytest.raises(ValueError, match='protected memory range'):
        C166Memory(protected_ranges=((2, 2),))


def test_unsupported_instruction_and_step_limit_fail_closed():
    decoder, memory = machine({0x20000: 'ff00'})
    with pytest.raises(C166ExecutionError, match='unsupported instruction'):
        C166CPU(decoder, memory).run()

    decoder, memory = machine({0x20000: '0dff'})
    with pytest.raises(C166ExecutionError, match='exceeded 2 execution steps'):
        C166CPU(decoder, memory).run(max_steps=2)


def test_can_message_objects_and_validation():
    memory = C166Memory()
    controller = C166CANController()
    message = C166CANMessage(0x06)

    controller.write_frame(memory, 1, message)

    assert controller.object_address(1) == 0xEF20
    assert controller.read_frame(memory, 1) == bytes.fromhex('06 00 00 00 00 00 00 06')
    assert message.checksum_valid
    assert not C166CANMessage(0x06, checksum=0).checksum_valid
    with pytest.raises(ValueError, match='four bytes'):
        C166CANMessage(0x06, payload=b'bad')
    with pytest.raises(TypeError, match='must be bytes'):
        C166CANMessage(0x06, payload=[0, 0, 0, 0])
    with pytest.raises(ValueError, match='object index'):
        controller.object_address(15)


def run_a1396_update(invalid_trigger: bool, invalid_arm: bool = False):
    image = A1396.read_bytes()
    decoder = EcuC166Decoder(image)
    memory = C166Memory(
        image,
        dpp_pages={1: 7},
        protected_ranges=((0x1C000, 0x1DACC), (0x20000, 0x2A72C)),
    )
    controller = C166CANController()
    memory.write16(0x83C6, controller.object_address(0))
    memory.write16(0x83C8, controller.object_address(1))
    memory.write(0xEF01, b'\x08')
    memory.write(0x8374, b'\x00')
    memory.write(0x84FE, b'\x00')
    cpu = C166CPU(decoder, memory, pc=0x237B2)

    def deliver(command: int, invalid: bool = False) -> None:
        message = C166CANMessage(command, checksum=0 if invalid else None)
        controller.write_frame(memory, 1, message)
        memory.write(0x838F, bytes((command, message.channel, message.subcommand)))
        memory.write(0x8387, bytes((0 if invalid else 7,)))

    deliver(0x06, invalid_arm)
    arm = cpu.run(stop_addresses={0x2492A})
    if invalid_arm:
        return arm, None, memory
    deliver(0x07, invalid_trigger)
    cpu.pc = 0x237B2
    trigger = cpu.run()
    return arm, trigger, memory


@pytest.mark.skipif(not A1396.is_file(), reason='A1396 analysis image not available')
@pytest.mark.parametrize('invalid_trigger', [False, True])
def test_real_a1396_can_update_execution(invalid_trigger):
    arm, trigger, memory = run_a1396_update(invalid_trigger)

    assert arm.reason == 'stop_address'
    assert arm.pc == 0x2492A
    assert memory.read(0x84FE) == b'\x07'
    assert trigger.reason == 'srst'
    assert trigger.pc == 0x248A4
    assert memory.read(0xF800, 10) == b'update req'
    assert memory.read(0x8374) == b'\x00'
    assert any(entry.pc == 0x247E6 for entry in arm.trace)
    assert any(entry.pc == 0x24868 for entry in trigger.trace)


@pytest.mark.skipif(not A1396.is_file(), reason='A1396 analysis image not available')
def test_real_a1396_invalid_arm_does_not_set_update_state():
    arm, trigger, memory = run_a1396_update(False, invalid_arm=True)

    assert arm.reason == 'stop_address'
    assert arm.pc == 0x2492A
    assert trigger is None
    assert memory.read(0x84FE) == b'\x00'
    assert not any(entry.pc == 0x247E6 for entry in arm.trace)
