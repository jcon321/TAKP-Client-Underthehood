# Source this to put the portable Ghidra/JDK/Node toolchain on PATH:
#   source ~/my-eqmac/TAKP-Client-Underthehood/tools/env.sh
TAKP_TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export JAVA_HOME="$TAKP_TOOLS/jdk"
export GHIDRA_INSTALL_DIR="$TAKP_TOOLS/ghidra"
export NPM_CONFIG_PREFIX="$TAKP_TOOLS/npm-global"
export NPM_CONFIG_CACHE="$TAKP_TOOLS/npm-cache"
export PATH="$TAKP_TOOLS/npm-global/bin:$TAKP_TOOLS/node/bin:$JAVA_HOME/bin:$GHIDRA_INSTALL_DIR/support:$PATH"
