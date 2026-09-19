# scenario_common.sh -- shared helpers for the scenario_NN_*.sh pentest
# scripts, sourced (not executed) by each one:
#
#     source "$(dirname "$0")/lib/scenario_common.sh"
#
# Holds only what was byte-identical across every scenario: the ANSI colour
# palette and the section banner(). Each scenario keeps its own config
# parsing, counters, and check() -- those genuinely differ (route-header vs.
# status vs. body vs. docker checks), so they're deliberately NOT here.
#
# Colours are silently harmless on a terminal that doesn't interpret them
# (printf writes the raw escapes; most CI logs strip them). BLUE is defined
# for the scenarios that use it; the rest simply never reference it.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # no colour

# Print a section banner.
banner() {
    printf "\n${CYAN}================================================================${NC}\n"
    printf "${CYAN}  %s${NC}\n" "$1"
    printf "${CYAN}================================================================${NC}\n\n"
}
