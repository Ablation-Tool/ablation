"""
Tests for HDLWritePath.

Mirrors the ALICE OPTIN register-file structure: a bus-target entity, a
registers entity with an address-decoded command register and one-cycle
strobe, a command decoder, and a top level wiring them together. Validated
against the real OPTIN and processing sources during development; the chains
below are the same shapes (alias slices, labeled end process, case-arm bank
decode, when/else concurrent assignments).
"""

import pytest

from ablation.analyzers.hdl_write_path import HDLWritePath


BUS_TARGET = """\
entity bus_target is
    port (
        clk        : in std_logic;
        address_in : in std_logic_vector(11 downto 0);
        write_out  : out std_logic
    );
end bus_target;
architecture RTL of bus_target is
    signal registers_write_en_i : std_logic;
begin
    write_out <= registers_write_en_i;
    process (clk)
    begin
        if (clk'event and clk='1') then
            case state is
                when s_bwr_data_phase =>
                    registers_write_en_i <= '1';
                when others =>
                    registers_write_en_i <= '0';
            end case;
        end if;
    end process;
end RTL;
"""

REGISTERS = """\
entity optin_registers is
    port (
        clk           : in std_logic;
        reset_n       : in std_logic;
        address       : in std_logic_vector(10 downto 0);
        data_in       : in std_logic_vector(31 downto 0);
        write_en      : in std_logic;
        optin_command : out std_logic_vector(31 downto 0);
        optin_command_en : out std_logic
    );
end optin_registers;
architecture RTL of optin_registers is
    constant ADDR_OPTIN_COMMAND : std_logic_vector (7 downto 0) := X"02";
    alias address_field : std_logic_vector(7 downto 0) is address(7 downto 0);
    signal int_block0_write_en : std_logic;
    signal reg_block0_write_en : std_logic;
    signal reg_address : std_logic_vector(7 downto 0);
    signal reg_optin_command : std_logic_vector(31 downto 0);
    signal reg_optin_command_en : std_logic;
begin
    optin_command <= reg_optin_command;
    optin_command_en <= reg_optin_command_en;
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            int_block0_write_en <= '0';
        elsif (clk'event and clk='1') then
            case depth_extension_field is
                when SELECT_BANK0 =>
                    int_block0_write_en <= write_en after DELAY;
                when others =>
                    int_block0_write_en <= '0' after DELAY;
            end case;
        end if;
    end process;
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            reg_block0_write_en <= '0';
        elsif (clk'event and clk='1') then
            reg_block0_write_en <= int_block0_write_en after DELAY;
        end if;
    end process PROCESS_REG_WRITE_EN;
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            reg_optin_command_en <= '0' after DELAY;
        elsif (clk'event and clk='1') then
            if (reg_block0_write_en = '1' and reg_address = ADDR_OPTIN_COMMAND) then
                reg_optin_command_en <= '1' after DELAY;
            else
                reg_optin_command_en <= '0' after DELAY;
            end if;
        end if;
    end process;
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            reg_optin_command <= X"00000000";
        elsif (clk'event and clk='1') then
            if (reg_block0_write_en = '1' and reg_address = ADDR_OPTIN_COMMAND) then
                reg_optin_command <= data_in after DELAY;
            end if;
        end if;
    end process;
end RTL;
"""

DECODER = """\
entity optin_command_decoder is
    port (
        clk              : in std_logic;
        optin_command    : in std_logic_vector(31 downto 0);
        optin_command_en : in std_logic;
        reset_parameters_n : out std_logic
    );
end optin_command_decoder;
architecture RTL of optin_command_decoder is
begin
    reset_parameters_n <= '0' when (optin_command_en = '1' and optin_command = X"FF000000") else '1';
end RTL;
"""

TOP = """\
entity optin_fpga_top is
    port (
        clk      : in std_logic;
        reset1   : in std_logic;
        bus_addr : in std_logic_vector(11 downto 0);
        bus_data : in std_logic_vector(31 downto 0)
    );
end optin_fpga_top;
architecture RTL of optin_fpga_top is
    alias device_field : std_logic_vector(3 downto 0) is bus_addr(11 downto 8);
    signal optin_registers_write : std_logic;
    signal optin_command : std_logic_vector(31 downto 0);
    signal optin_command_en : std_logic;
    signal int_reset_n : std_logic;
begin
    int_reset_n <= reset1;
    INST_BUS_TARGET: bus_target
        port map (
            clk => clk,
            address_in => bus_addr,
            write_out => optin_registers_write
        );
    INST_OPTIN_REGISTERS: optin_registers
        port map (
            clk => clk,
            reset_n => int_reset_n,
            address => bus_addr(10 downto 0),
            data_in => bus_data,
            write_en => optin_registers_write,
            optin_command => optin_command,
            optin_command_en => optin_command_en
        );
    INST_DECODER: entity work.optin_command_decoder
        port map (
            clk => clk,
            optin_command => optin_command,
            optin_command_en => optin_command_en,
            reset_parameters_n => open
        );
end RTL;
"""


@pytest.fixture
def tracer(tmp_path):
    for name, content in [
        ("bus_target.vhd", BUS_TARGET),
        ("optin_registers.vhd", REGISTERS),
        ("optin_command_decoder.vhd", DECODER),
        ("optin_fpga_top.vhd", TOP),
    ]:
        (tmp_path / name).write_text(content)
    return HDLWritePath.from_directory(str(tmp_path))


def test_ports_fully_parsed(tracer):
    ports = tracer.entities["optin_registers"].ports
    assert ports["write_en"] == "in"
    assert ports["data_in"] == "in"
    assert ports["optin_command"] == "out"
    assert ports["optin_command_en"] == "out"


def test_strobe_reaches_bus_and_decoder_not_a_driver(tracer):
    report = tracer.trace("optin_registers.optin_command_en")
    # The chain crosses the top level into the bus-target entity.
    assert any(
        h.entity == "bus_target" and h.signal == "registers_write_en_i"
        for path in report.paths for h in path
    )
    # The decoder's input port must never appear as a driver of the strobe.
    for path in report.paths:
        assert not any(
            h.entity == "optin_command_decoder" and h.signal == "optin_command_en"
            for h in path
        )
    # Address decode condition and its constant are recovered.
    assert any("ADDR_OPTIN_COMMAND" in c for c in report.conditions)
    assert report.address_constants["ADDR_OPTIN_COMMAND"] == "0x02"


def test_strobe_chain_shape(tracer):
    report = tracer.trace("optin_registers.optin_command_en")
    found = False
    for path in report.paths:
        signals = [h.scoped() for h in path]
        if "bus_target.registers_write_en_i" in signals or "bus_target.write_out" in signals:
            found = True
            assert signals[0] == "optin_registers.optin_command_en"
            assert "optin_registers.reg_optin_command_en" in signals
            assert "optin_registers.reg_block0_write_en" in signals
            assert "optin_registers.int_block0_write_en" in signals
            assert "optin_registers.write_en" in signals
            break
    assert found, f"no path through the bus target; got {len(report.paths)} paths"


def test_command_data_path(tracer):
    report = tracer.trace("optin_registers.optin_command")
    for path in report.paths:
        signals = [h.scoped() for h in path]
        if signals[-1] == "optin_fpga_top.bus_data":
            assert "optin_registers.reg_optin_command" in signals
            assert "optin_registers.data_in" in signals
            break
    else:
        raise AssertionError(f"no bus_data path; inputs={report.primary_inputs}")


def test_case_arm_conditions_do_not_leak(tracer):
    entity = tracer.entities["optin_registers"]
    by_cond = {}
    for assign in entity.assignments:
        if assign.target == "int_block0_write_en":
            by_cond[assign.expression] = assign.conditions
    assert by_cond["write_en"] == ["depth_extension_field = SELECT_BANK0"]
    assert by_cond["'0'"][0] in {"reset_n = '0'", "depth_extension_field = others"}
    # The reset assignment carries only the reset condition, not the case arms.
    reset_assign = entity.assignments
    assert not any(
        a.target == "int_block0_write_en" and "reset_n = '0'" in a.conditions
        and any("SELECT_BANK0" in c for c in a.conditions)
        for a in reset_assign
    )


def test_else_branch_inverts_condition(tracer):
    entity = tracer.entities["optin_registers"]
    else_assigns = [
        a for a in entity.assignments
        if a.target == "reg_optin_command_en" and a.expression == "'0'"
        and any(c.startswith("not (") for c in a.conditions)
    ]
    assert else_assigns, "else branch should carry the inverted write-decode condition"


def test_when_else_concurrent(tracer):
    entity = tracer.entities["optin_command_decoder"]
    assign = next(a for a in entity.assignments if a.target == "reset_parameters_n")
    assert assign.conditions == ["optin_command_en = '1' and optin_command = X\"FF000000\""]


def test_alias_hop(tracer):
    report = tracer.trace("optin_fpga_top.device_field")
    assert any(h.signal == "bus_addr" for path in report.paths for h in path)


def test_trace_decoder_convenience(tracer):
    reports = tracer.trace_decoder("optin_command_decoder",
                                   selector="optin_command", strobe="optin_command_en")
    assert set(reports) == {"command", "strobe"}
    assert reports["command"].paths
    assert reports["strobe"].paths


def test_unscoped_target_resolution(tracer):
    report = tracer.trace("reg_optin_command_en")
    assert report.target == "optin_registers.reg_optin_command_en"


def test_serialization(tracer):
    data = tracer.trace("optin_registers.optin_command_en").to_dict()
    assert data["target"] == "optin_registers.optin_command_en"
    assert data["address_constants"]["ADDR_OPTIN_COMMAND"] == "0x02"
    import json
    json.dumps(data)
