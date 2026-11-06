"""
Tests for HDLCommandDecoder.

Real-world anchors are the ALICE Pixel Trigger decoders (optin, processing,
control): constant-declared 32-bit and 8-bit command tables dispatched inside
clocked processes, gated only by a command strobe. Key regressions covered:
  - sibling if-statements before the case are not dispatch guards
  - `after DELAY` simulation delays are stripped from effects
  - `when others` arms are not commands
  - a functional guard (mode/unlock) makes the dispatch guarded
"""

import pytest

from ablation.analyzers.hdl_command_decoder import HDLCommandDecoder


VHDL_OPTIN_LIKE = """\
library ieee;
use ieee.std_logic_1164.all;

entity optin_command_decoder is
    port (
        clk             : in std_logic;
        reset_n         : in std_logic;
        optin_command   : in std_logic_vector(31 downto 0);
        optin_command_en : in std_logic;
        reset_parameters_n : out std_logic
    );
end optin_command_decoder;

architecture RTL of optin_command_decoder is
    constant COMMAND_RESET_PARAMETERS : std_logic_vector (31 downto 0) := X"FF000000";
    constant COMMAND_STROBE_TIMESTAMPING : std_logic_vector (31 downto 0) := X"F0000000";
    signal int_reset_parameters_n : std_logic := '1';
begin
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            int_reset_parameters_n <= '1' after DELAY;
        elsif (clk'event and clk='1') then
            int_reset_parameters_n <= '1' after DELAY;
            if (optin_command_en = '1') then
                case optin_command is
                    when COMMAND_RESET_PARAMETERS =>
                        int_reset_parameters_n <= '0' after DELAY;
                        assert false report "reset" severity note;
                    when COMMAND_STROBE_TIMESTAMPING =>
                        int_reset_parameters_n <= '1' after DELAY;
                    when X"8000001F" =>
                        int_reset_parameters_n <= '1' after DELAY;
                    when others =>
                        int_reset_parameters_n <= '1' after DELAY;
                end case;
            end if;
        end if;
    end process;
end RTL;
"""

# Mirrors the control FPGA: an automatic-reset sibling if before the dispatch.
VHDL_SIBLING_IF = """\
architecture RTL of control_decoder is
    constant COMMAND_RESET_BUS_MASTER : std_logic_vector (7 downto 0) := X"A0";
begin
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            pulse_reset_optin <= (others => '0');
        elsif (clk'event and clk='1') then
            if (automatic_optin_reset_pulse = '1') then
                pulse_reset_optin <= (others => '1');
            else
                pulse_reset_optin <= (others => '0');
            end if;
            if (command_strobe = '1') then
                case (command) is
                    when COMMAND_RESET_BUS_MASTER =>
                        pulse_reset_bus_master <= '1' after DELAY;
                    when others =>
                        pulse_reset_bus_master <= '0' after DELAY;
                end case;
            end if;
        end if;
    end process;
end RTL;
"""

VHDL_GUARDED = """\
architecture RTL of secure_decoder is
    constant COMMAND_ERASE : std_logic_vector (7 downto 0) := X"EE";
begin
    process (clk, reset_n)
    begin
        if (reset_n = '0') then
            erase <= '0';
        elsif (clk'event and clk='1') then
            if (command_strobe = '1' and mode_unlocked = '1') then
                case command is
                    when COMMAND_ERASE =>
                        erase <= '1';
                    when others =>
                        erase <= '0';
                end case;
            end if;
        end if;
    end process;
end RTL;
"""

VERILOG_DECODER = """\
module cmd_decoder (
    input wire clk,
    input wire [7:0] command,
    input wire command_strobe,
    output reg reset_out
);
    localparam CMD_RESET = 8'hA0;
    parameter CMD_START = 8'hB0;

    always @(posedge clk) begin
        if (command_strobe) begin
            case (command)
                CMD_RESET: reset_out <= 1'b1;
                CMD_START: reset_out <= 1'b0;
                default: reset_out <= 1'b0;
            endcase
        end
    end
endmodule
"""

VERILOG_GUARDED = """\
module guarded_decoder (
    input wire clk,
    input wire [7:0] command,
    input wire command_strobe,
    input wire authenticated,
    output reg reset_out
);
    localparam CMD_RESET = 8'hA0;
    always @(posedge clk) begin
        if (command_strobe && authenticated) begin
            case (command)
                CMD_RESET: reset_out <= 1'b1;
            endcase
        end
    end
endmodule
"""


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return str(path)


def test_vhdl_constants_and_effects(tmp_path):
    dec = HDLCommandDecoder.from_file(_write(tmp_path, "optin_command_decoder.vhd", VHDL_OPTIN_LIKE))
    assert len(dec.reports) == 1
    report = dec.reports[0]
    assert report.selector == "optin_command"
    assert report.unguarded
    assert "reset_n = '0'" in report.guards
    assert "optin_command_en = '1'" in report.guards
    by_name = {c.name: c for c in report.commands}
    assert by_name["COMMAND_RESET_PARAMETERS"].value == "0xFF000000"
    assert by_name["COMMAND_STROBE_TIMESTAMPING"].value == "0xF0000000"
    assert by_name['X"8000001F"'].value == "0x8000001F"
    assert "others" not in by_name
    effects = by_name["COMMAND_RESET_PARAMETERS"].effects
    assert len(effects) == 1
    assert effects[0].signal == "int_reset_parameters_n"
    assert effects[0].value == "'0'"  # after DELAY stripped
    # assert/report lines are not signal effects
    assert all("assert" not in e.signal for e in effects)


def test_vhdl_sibling_if_is_not_a_guard(tmp_path):
    dec = HDLCommandDecoder.from_file(_write(tmp_path, "command_decoder.vhd", VHDL_SIBLING_IF))
    report = dec.reports[0]
    assert report.unguarded
    assert report.guards == ["reset_n = '0'", "command_strobe = '1'"]
    assert report.commands[0].value == "0xA0"


def test_vhdl_functional_guard_marks_guarded(tmp_path):
    dec = HDLCommandDecoder.from_file(_write(tmp_path, "secure_decoder.vhd", VHDL_GUARDED))
    report = dec.reports[0]
    assert not report.unguarded
    assert any("mode_unlocked" in g for g in report.guards)


def test_verilog_decoder(tmp_path):
    dec = HDLCommandDecoder.from_file(_write(tmp_path, "cmd_decoder.v", VERILOG_DECODER))
    assert len(dec.reports) == 1
    report = dec.reports[0]
    assert report.selector == "command"
    assert report.unguarded
    by_name = {c.name: c for c in report.commands}
    assert by_name["CMD_RESET"].value == "0xA0"
    assert by_name["CMD_START"].value == "0xB0"
    assert "default" not in by_name
    assert by_name["CMD_RESET"].effects[0].signal == "reset_out"
    assert by_name["CMD_RESET"].effects[0].value == "1'b1"


def test_verilog_guarded(tmp_path):
    dec = HDLCommandDecoder.from_file(_write(tmp_path, "guarded_decoder.v", VERILOG_GUARDED))
    assert not dec.reports[0].unguarded


def test_directory_scan_and_serialization(tmp_path):
    _write(tmp_path, "a.vhd", VHDL_OPTIN_LIKE)
    _write(tmp_path, "b.v", VERILOG_DECODER)
    _write(tmp_path, "ignored.txt", "case ignored is")
    dec = HDLCommandDecoder.from_directory(str(tmp_path))
    assert len(dec.reports) == 2
    data = dec.to_dict()
    assert data["total_commands"] == 5
    assert data["unguarded_decoders"] == 2
    text = dec.summary()
    assert "0xFF000000" in text
    assert "UNGUARDED" in text


def test_no_decoders(tmp_path):
    dec = HDLCommandDecoder.from_file(_write(tmp_path, "empty.vhd", "architecture RTL of x is\nbegin\nend RTL;\n"))
    assert dec.reports == []
    assert dec.summary() == "no command decoders found"
