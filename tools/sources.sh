# Community reference sources used by analyze.sh / refine.sh (sibling repos in ~/my-eqmac).
_REF="$(dirname "$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")")"
MQ2_H="$_REF/MyAKMQ2/MQ2Main/eqgame.h"
MQ2_GLOBALS="$_REF/MyAKMQ2/MQ2Main/MQ2Globals.cpp"
ZEAL_H="$_REF/Zeal/Zeal/game_addresses.h"
# Struct layout headers; earlier ones win when a struct name repeats.
STRUCT_HEADERS=(
	"$_REF/Zeal/Zeal/game_structures.h"
	"$_REF/Zeal/Zeal/game_ui.h"
	"$_REF/MyAKMQ2/MQ2Main/EQData.h"
	"$_REF/MyAKMQ2/MQ2Main/EQUIStructs.h"
)
