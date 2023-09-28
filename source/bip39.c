/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 David L. Whitehurst
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * conversion.c (source)
 * Reusable conversion (beyond casting) functions.
 *
 * author: David L. Whitehurst
 * date: June 8, 2018
 *
 * Find this code useful? Please donate:
 *  Bitcoin: 1Mxt427mTF3XGf8BiJ8HjkhbiSVvJbkDFY
 *
 */

#include <aws/nitro_enclaves/bip39.h>

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/*
 * Global variables
 */

char *words[LANG_WORD_CNT] = {
    "abandon",  "ability",  "able",     "about",    "above",    "absent",   "absorb",   "abstract", "absurd",
    "abuse",    "access",   "accident", "account",  "accuse",   "achieve",  "acid",     "acoustic", "acquire",
    "across",   "act",      "action",   "actor",    "actress",  "actual",   "adapt",    "add",      "addict",
    "address",  "adjust",   "admit",    "adult",    "advance",  "advice",   "aerobic",  "affair",   "afford",
    "afraid",   "again",    "age",      "agent",    "agree",    "ahead",    "aim",      "air",      "airport",
    "aisle",    "alarm",    "album",    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",
    "almost",   "alone",    "alpha",    "already",  "also",     "alter",    "always",   "amateur",  "amazing",
    "among",    "amount",   "amused",   "analyst",  "anchor",   "ancient",  "anger",    "angle",    "angry",
    "animal",   "ankle",    "announce", "annual",   "another",  "answer",   "antenna",  "antique",  "anxiety",
    "any",      "apart",    "apology",  "appear",   "apple",    "approve",  "april",    "arch",     "arctic",
    "area",     "arena",    "argue",    "arm",      "armed",    "armor",    "army",     "around",   "arrange",
    "arrest",   "arrive",   "arrow",    "art",      "artefact", "artist",   "artwork",  "ask",      "aspect",
    "assault",  "asset",    "assist",   "assume",   "asthma",   "athlete",  "atom",     "attack",   "attend",
    "attitude", "attract",  "auction",  "audit",    "august",   "aunt",     "author",   "auto",     "autumn",
    "average",  "avocado",  "avoid",    "awake",    "aware",    "away",     "awesome",  "awful",    "awkward",
    "axis",     "baby",     "bachelor", "bacon",    "badge",    "bag",      "balance",  "balcony",  "ball",
    "bamboo",   "banana",   "banner",   "bar",      "barely",   "bargain",  "barrel",   "base",     "basic",
    "basket",   "battle",   "beach",    "bean",     "beauty",   "because",  "become",   "beef",     "before",
    "begin",    "behave",   "behind",   "believe",  "below",    "belt",     "bench",    "benefit",  "best",
    "betray",   "better",   "between",  "beyond",   "bicycle",  "bid",      "bike",     "bind",     "biology",
    "bird",     "birth",    "bitter",   "black",    "blade",    "blame",    "blanket",  "blast",    "bleak",
    "bless",    "blind",    "blood",    "blossom",  "blouse",   "blue",     "blur",     "blush",    "board",
    "boat",     "body",     "boil",     "bomb",     "bone",     "bonus",    "book",     "boost",    "border",
    "boring",   "borrow",   "boss",     "bottom",   "bounce",   "box",      "boy",      "bracket",  "brain",
    "brand",    "brass",    "brave",    "bread",    "breeze",   "brick",    "bridge",   "brief",    "bright",
    "bring",    "brisk",    "broccoli", "broken",   "bronze",   "broom",    "brother",  "brown",    "brush",
    "bubble",   "buddy",    "budget",   "buffalo",  "build",    "bulb",     "bulk",     "bullet",   "bundle",
    "bunker",   "burden",   "burger",   "burst",    "bus",      "business", "busy",     "butter",   "buyer",
    "buzz",     "cabbage",  "cabin",    "cable",    "cactus",   "cage",     "cake",     "call",     "calm",
    "camera",   "camp",     "can",      "canal",    "cancel",   "candy",    "cannon",   "canoe",    "canvas",
    "canyon",   "capable",  "capital",  "captain",  "car",      "carbon",   "card",     "cargo",    "carpet",
    "carry",    "cart",     "case",     "cash",     "casino",   "castle",   "casual",   "cat",      "catalog",
    "catch",    "category", "cattle",   "caught",   "cause",    "caution",  "cave",     "ceiling",  "celery",
    "cement",   "census",   "century",  "cereal",   "certain",  "chair",    "chalk",    "champion", "change",
    "chaos",    "chapter",  "charge",   "chase",    "chat",     "cheap",    "check",    "cheese",   "chef",
    "cherry",   "chest",    "chicken",  "chief",    "child",    "chimney",  "choice",   "choose",   "chronic",
    "chuckle",  "chunk",    "churn",    "cigar",    "cinnamon", "circle",   "citizen",  "city",     "civil",
    "claim",    "clap",     "clarify",  "claw",     "clay",     "clean",    "clerk",    "clever",   "click",
    "client",   "cliff",    "climb",    "clinic",   "clip",     "clock",    "clog",     "close",    "cloth",
    "cloud",    "clown",    "club",     "clump",    "cluster",  "clutch",   "coach",    "coast",    "coconut",
    "code",     "coffee",   "coil",     "coin",     "collect",  "color",    "column",   "combine",  "come",
    "comfort",  "comic",    "common",   "company",  "concert",  "conduct",  "confirm",  "congress", "connect",
    "consider", "control",  "convince", "cook",     "cool",     "copper",   "copy",     "coral",    "core",
    "corn",     "correct",  "cost",     "cotton",   "couch",    "country",  "couple",   "course",   "cousin",
    "cover",    "coyote",   "crack",    "cradle",   "craft",    "cram",     "crane",    "crash",    "crater",
    "crawl",    "crazy",    "cream",    "credit",   "creek",    "crew",     "cricket",  "crime",    "crisp",
    "critic",   "crop",     "cross",    "crouch",   "crowd",    "crucial",  "cruel",    "cruise",   "crumble",
    "crunch",   "crush",    "cry",      "crystal",  "cube",     "culture",  "cup",      "cupboard", "curious",
    "current",  "curtain",  "curve",    "cushion",  "custom",   "cute",     "cycle",    "dad",      "damage",
    "damp",     "dance",    "danger",   "daring",   "dash",     "daughter", "dawn",     "day",      "deal",
    "debate",   "debris",   "decade",   "december", "decide",   "decline",  "decorate", "decrease", "deer",
    "defense",  "define",   "defy",     "degree",   "delay",    "deliver",  "demand",   "demise",   "denial",
    "dentist",  "deny",     "depart",   "depend",   "deposit",  "depth",    "deputy",   "derive",   "describe",
    "desert",   "design",   "desk",     "despair",  "destroy",  "detail",   "detect",   "develop",  "device",
    "devote",   "diagram",  "dial",     "diamond",  "diary",    "dice",     "diesel",   "diet",     "differ",
    "digital",  "dignity",  "dilemma",  "dinner",   "dinosaur", "direct",   "dirt",     "disagree", "discover",
    "disease",  "dish",     "dismiss",  "disorder", "display",  "distance", "divert",   "divide",   "divorce",
    "dizzy",    "doctor",   "document", "dog",      "doll",     "dolphin",  "domain",   "donate",   "donkey",
    "donor",    "door",     "dose",     "double",   "dove",     "draft",    "dragon",   "drama",    "drastic",
    "draw",     "dream",    "dress",    "drift",    "drill",    "drink",    "drip",     "drive",    "drop",
    "drum",     "dry",      "duck",     "dumb",     "dune",     "during",   "dust",     "dutch",    "duty",
    "dwarf",    "dynamic",  "eager",    "eagle",    "early",    "earn",     "earth",    "easily",   "east",
    "easy",     "echo",     "ecology",  "economy",  "edge",     "edit",     "educate",  "effort",   "egg",
    "eight",    "either",   "elbow",    "elder",    "electric", "elegant",  "element",  "elephant", "elevator",
    "elite",    "else",     "embark",   "embody",   "embrace",  "emerge",   "emotion",  "employ",   "empower",
    "empty",    "enable",   "enact",    "end",      "endless",  "endorse",  "enemy",    "energy",   "enforce",
    "engage",   "engine",   "enhance",  "enjoy",    "enlist",   "enough",   "enrich",   "enroll",   "ensure",
    "enter",    "entire",   "entry",    "envelope", "episode",  "equal",    "equip",    "era",      "erase",
    "erode",    "erosion",  "error",    "erupt",    "escape",   "essay",    "essence",  "estate",   "eternal",
    "ethics",   "evidence", "evil",     "evoke",    "evolve",   "exact",    "example",  "excess",   "exchange",
    "excite",   "exclude",  "excuse",   "execute",  "exercise", "exhaust",  "exhibit",  "exile",    "exist",
    "exit",     "exotic",   "expand",   "expect",   "expire",   "explain",  "expose",   "express",  "extend",
    "extra",    "eye",      "eyebrow",  "fabric",   "face",     "faculty",  "fade",     "faint",    "faith",
    "fall",     "false",    "fame",     "family",   "famous",   "fan",      "fancy",    "fantasy",  "farm",
    "fashion",  "fat",      "fatal",    "father",   "fatigue",  "fault",    "favorite", "feature",  "february",
    "federal",  "fee",      "feed",     "feel",     "female",   "fence",    "festival", "fetch",    "fever",
    "few",      "fiber",    "fiction",  "field",    "figure",   "file",     "film",     "filter",   "final",
    "find",     "fine",     "finger",   "finish",   "fire",     "firm",     "first",    "fiscal",   "fish",
    "fit",      "fitness",  "fix",      "flag",     "flame",    "flash",    "flat",     "flavor",   "flee",
    "flight",   "flip",     "float",    "flock",    "floor",    "flower",   "fluid",    "flush",    "fly",
    "foam",     "focus",    "fog",      "foil",     "fold",     "follow",   "food",     "foot",     "force",
    "forest",   "forget",   "fork",     "fortune",  "forum",    "forward",  "fossil",   "foster",   "found",
    "fox",      "fragile",  "frame",    "frequent", "fresh",    "friend",   "fringe",   "frog",     "front",
    "frost",    "frown",    "frozen",   "fruit",    "fuel",     "fun",      "funny",    "furnace",  "fury",
    "future",   "gadget",   "gain",     "galaxy",   "gallery",  "game",     "gap",      "garage",   "garbage",
    "garden",   "garlic",   "garment",  "gas",      "gasp",     "gate",     "gather",   "gauge",    "gaze",
    "general",  "genius",   "genre",    "gentle",   "genuine",  "gesture",  "ghost",    "giant",    "gift",
    "giggle",   "ginger",   "giraffe",  "girl",     "give",     "glad",     "glance",   "glare",    "glass",
    "glide",    "glimpse",  "globe",    "gloom",    "glory",    "glove",    "glow",     "glue",     "goat",
    "goddess",  "gold",     "good",     "goose",    "gorilla",  "gospel",   "gossip",   "govern",   "gown",
    "grab",     "grace",    "grain",    "grant",    "grape",    "grass",    "gravity",  "great",    "green",
    "grid",     "grief",    "grit",     "grocery",  "group",    "grow",     "grunt",    "guard",    "guess",
    "guide",    "guilt",    "guitar",   "gun",      "gym",      "habit",    "hair",     "half",     "hammer",
    "hamster",  "hand",     "happy",    "harbor",   "hard",     "harsh",    "harvest",  "hat",      "have",
    "hawk",     "hazard",   "head",     "health",   "heart",    "heavy",    "hedgehog", "height",   "hello",
    "helmet",   "help",     "hen",      "hero",     "hidden",   "high",     "hill",     "hint",     "hip",
    "hire",     "history",  "hobby",    "hockey",   "hold",     "hole",     "holiday",  "hollow",   "home",
    "honey",    "hood",     "hope",     "horn",     "horror",   "horse",    "hospital", "host",     "hotel",
    "hour",     "hover",    "hub",      "huge",     "human",    "humble",   "humor",    "hundred",  "hungry",
    "hunt",     "hurdle",   "hurry",    "hurt",     "husband",  "hybrid",   "ice",      "icon",     "idea",
    "identify", "idle",     "ignore",   "ill",      "illegal",  "illness",  "image",    "imitate",  "immense",
    "immune",   "impact",   "impose",   "improve",  "impulse",  "inch",     "include",  "income",   "increase",
    "index",    "indicate", "indoor",   "industry", "infant",   "inflict",  "inform",   "inhale",   "inherit",
    "initial",  "inject",   "injury",   "inmate",   "inner",    "innocent", "input",    "inquiry",  "insane",
    "insect",   "inside",   "inspire",  "install",  "intact",   "interest", "into",     "invest",   "invite",
    "involve",  "iron",     "island",   "isolate",  "issue",    "item",     "ivory",    "jacket",   "jaguar",
    "jar",      "jazz",     "jealous",  "jeans",    "jelly",    "jewel",    "job",      "join",     "joke",
    "journey",  "joy",      "judge",    "juice",    "jump",     "jungle",   "junior",   "junk",     "just",
    "kangaroo", "keen",     "keep",     "ketchup",  "key",      "kick",     "kid",      "kidney",   "kind",
    "kingdom",  "kiss",     "kit",      "kitchen",  "kite",     "kitten",   "kiwi",     "knee",     "knife",
    "knock",    "know",     "lab",      "label",    "labor",    "ladder",   "lady",     "lake",     "lamp",
    "language", "laptop",   "large",    "later",    "latin",    "laugh",    "laundry",  "lava",     "law",
    "lawn",     "lawsuit",  "layer",    "lazy",     "leader",   "leaf",     "learn",    "leave",    "lecture",
    "left",     "leg",      "legal",    "legend",   "leisure",  "lemon",    "lend",     "length",   "lens",
    "leopard",  "lesson",   "letter",   "level",    "liar",     "liberty",  "library",  "license",  "life",
    "lift",     "light",    "like",     "limb",     "limit",    "link",     "lion",     "liquid",   "list",
    "little",   "live",     "lizard",   "load",     "loan",     "lobster",  "local",    "lock",     "logic",
    "lonely",   "long",     "loop",     "lottery",  "loud",     "lounge",   "love",     "loyal",    "lucky",
    "luggage",  "lumber",   "lunar",    "lunch",    "luxury",   "lyrics",   "machine",  "mad",      "magic",
    "magnet",   "maid",     "mail",     "main",     "major",    "make",     "mammal",   "man",      "manage",
    "mandate",  "mango",    "mansion",  "manual",   "maple",    "marble",   "march",    "margin",   "marine",
    "market",   "marriage", "mask",     "mass",     "master",   "match",    "material", "math",     "matrix",
    "matter",   "maximum",  "maze",     "meadow",   "mean",     "measure",  "meat",     "mechanic", "medal",
    "media",    "melody",   "melt",     "member",   "memory",   "mention",  "menu",     "mercy",    "merge",
    "merit",    "merry",    "mesh",     "message",  "metal",    "method",   "middle",   "midnight", "milk",
    "million",  "mimic",    "mind",     "minimum",  "minor",    "minute",   "miracle",  "mirror",   "misery",
    "miss",     "mistake",  "mix",      "mixed",    "mixture",  "mobile",   "model",    "modify",   "mom",
    "moment",   "monitor",  "monkey",   "monster",  "month",    "moon",     "moral",    "more",     "morning",
    "mosquito", "mother",   "motion",   "motor",    "mountain", "mouse",    "move",     "movie",    "much",
    "muffin",   "mule",     "multiply", "muscle",   "museum",   "mushroom", "music",    "must",     "mutual",
    "myself",   "mystery",  "myth",     "naive",    "name",     "napkin",   "narrow",   "nasty",    "nation",
    "nature",   "near",     "neck",     "need",     "negative", "neglect",  "neither",  "nephew",   "nerve",
    "nest",     "net",      "network",  "neutral",  "never",    "news",     "next",     "nice",     "night",
    "noble",    "noise",    "nominee",  "noodle",   "normal",   "north",    "nose",     "notable",  "note",
    "nothing",  "notice",   "novel",    "now",      "nuclear",  "number",   "nurse",    "nut",      "oak",
    "obey",     "object",   "oblige",   "obscure",  "observe",  "obtain",   "obvious",  "occur",    "ocean",
    "october",  "odor",     "off",      "offer",    "office",   "often",    "oil",      "okay",     "old",
    "olive",    "olympic",  "omit",     "once",     "one",      "onion",    "online",   "only",     "open",
    "opera",    "opinion",  "oppose",   "option",   "orange",   "orbit",    "orchard",  "order",    "ordinary",
    "organ",    "orient",   "original", "orphan",   "ostrich",  "other",    "outdoor",  "outer",    "output",
    "outside",  "oval",     "oven",     "over",     "own",      "owner",    "oxygen",   "oyster",   "ozone",
    "pact",     "paddle",   "page",     "pair",     "palace",   "palm",     "panda",    "panel",    "panic",
    "panther",  "paper",    "parade",   "parent",   "park",     "parrot",   "party",    "pass",     "patch",
    "path",     "patient",  "patrol",   "pattern",  "pause",    "pave",     "payment",  "peace",    "peanut",
    "pear",     "peasant",  "pelican",  "pen",      "penalty",  "pencil",   "people",   "pepper",   "perfect",
    "permit",   "person",   "pet",      "phone",    "photo",    "phrase",   "physical", "piano",    "picnic",
    "picture",  "piece",    "pig",      "pigeon",   "pill",     "pilot",    "pink",     "pioneer",  "pipe",
    "pistol",   "pitch",    "pizza",    "place",    "planet",   "plastic",  "plate",    "play",     "please",
    "pledge",   "pluck",    "plug",     "plunge",   "poem",     "poet",     "point",    "polar",    "pole",
    "police",   "pond",     "pony",     "pool",     "popular",  "portion",  "position", "possible", "post",
    "potato",   "pottery",  "poverty",  "powder",   "power",    "practice", "praise",   "predict",  "prefer",
    "prepare",  "present",  "pretty",   "prevent",  "price",    "pride",    "primary",  "print",    "priority",
    "prison",   "private",  "prize",    "problem",  "process",  "produce",  "profit",   "program",  "project",
    "promote",  "proof",    "property", "prosper",  "protect",  "proud",    "provide",  "public",   "pudding",
    "pull",     "pulp",     "pulse",    "pumpkin",  "punch",    "pupil",    "puppy",    "purchase", "purity",
    "purpose",  "purse",    "push",     "put",      "puzzle",   "pyramid",  "quality",  "quantum",  "quarter",
    "question", "quick",    "quit",     "quiz",     "quote",    "rabbit",   "raccoon",  "race",     "rack",
    "radar",    "radio",    "rail",     "rain",     "raise",    "rally",    "ramp",     "ranch",    "random",
    "range",    "rapid",    "rare",     "rate",     "rather",   "raven",    "raw",      "razor",    "ready",
    "real",     "reason",   "rebel",    "rebuild",  "recall",   "receive",  "recipe",   "record",   "recycle",
    "reduce",   "reflect",  "reform",   "refuse",   "region",   "regret",   "regular",  "reject",   "relax",
    "release",  "relief",   "rely",     "remain",   "remember", "remind",   "remove",   "render",   "renew",
    "rent",     "reopen",   "repair",   "repeat",   "replace",  "report",   "require",  "rescue",   "resemble",
    "resist",   "resource", "response", "result",   "retire",   "retreat",  "return",   "reunion",  "reveal",
    "review",   "reward",   "rhythm",   "rib",      "ribbon",   "rice",     "rich",     "ride",     "ridge",
    "rifle",    "right",    "rigid",    "ring",     "riot",     "ripple",   "risk",     "ritual",   "rival",
    "river",    "road",     "roast",    "robot",    "robust",   "rocket",   "romance",  "roof",     "rookie",
    "room",     "rose",     "rotate",   "rough",    "round",    "route",    "royal",    "rubber",   "rude",
    "rug",      "rule",     "run",      "runway",   "rural",    "sad",      "saddle",   "sadness",  "safe",
    "sail",     "salad",    "salmon",   "salon",    "salt",     "salute",   "same",     "sample",   "sand",
    "satisfy",  "satoshi",  "sauce",    "sausage",  "save",     "say",      "scale",    "scan",     "scare",
    "scatter",  "scene",    "scheme",   "school",   "science",  "scissors", "scorpion", "scout",    "scrap",
    "screen",   "script",   "scrub",    "sea",      "search",   "season",   "seat",     "second",   "secret",
    "section",  "security", "seed",     "seek",     "segment",  "select",   "sell",     "seminar",  "senior",
    "sense",    "sentence", "series",   "service",  "session",  "settle",   "setup",    "seven",    "shadow",
    "shaft",    "shallow",  "share",    "shed",     "shell",    "sheriff",  "shield",   "shift",    "shine",
    "ship",     "shiver",   "shock",    "shoe",     "shoot",    "shop",     "short",    "shoulder", "shove",
    "shrimp",   "shrug",    "shuffle",  "shy",      "sibling",  "sick",     "side",     "siege",    "sight",
    "sign",     "silent",   "silk",     "silly",    "silver",   "similar",  "simple",   "since",    "sing",
    "siren",    "sister",   "situate",  "six",      "size",     "skate",    "sketch",   "ski",      "skill",
    "skin",     "skirt",    "skull",    "slab",     "slam",     "sleep",    "slender",  "slice",    "slide",
    "slight",   "slim",     "slogan",   "slot",     "slow",     "slush",    "small",    "smart",    "smile",
    "smoke",    "smooth",   "snack",    "snake",    "snap",     "sniff",    "snow",     "soap",     "soccer",
    "social",   "sock",     "soda",     "soft",     "solar",    "soldier",  "solid",    "solution", "solve",
    "someone",  "song",     "soon",     "sorry",    "sort",     "soul",     "sound",    "soup",     "source",
    "south",    "space",    "spare",    "spatial",  "spawn",    "speak",    "special",  "speed",    "spell",
    "spend",    "sphere",   "spice",    "spider",   "spike",    "spin",     "spirit",   "split",    "spoil",
    "sponsor",  "spoon",    "sport",    "spot",     "spray",    "spread",   "spring",   "spy",      "square",
    "squeeze",  "squirrel", "stable",   "stadium",  "staff",    "stage",    "stairs",   "stamp",    "stand",
    "start",    "state",    "stay",     "steak",    "steel",    "stem",     "step",     "stereo",   "stick",
    "still",    "sting",    "stock",    "stomach",  "stone",    "stool",    "story",    "stove",    "strategy",
    "street",   "strike",   "strong",   "struggle", "student",  "stuff",    "stumble",  "style",    "subject",
    "submit",   "subway",   "success",  "such",     "sudden",   "suffer",   "sugar",    "suggest",  "suit",
    "summer",   "sun",      "sunny",    "sunset",   "super",    "supply",   "supreme",  "sure",     "surface",
    "surge",    "surprise", "surround", "survey",   "suspect",  "sustain",  "swallow",  "swamp",    "swap",
    "swarm",    "swear",    "sweet",    "swift",    "swim",     "swing",    "switch",   "sword",    "symbol",
    "symptom",  "syrup",    "system",   "table",    "tackle",   "tag",      "tail",     "talent",   "talk",
    "tank",     "tape",     "target",   "task",     "taste",    "tattoo",   "taxi",     "teach",    "team",
    "tell",     "ten",      "tenant",   "tennis",   "tent",     "term",     "test",     "text",     "thank",
    "that",     "theme",    "then",     "theory",   "there",    "they",     "thing",    "this",     "thought",
    "three",    "thrive",   "throw",    "thumb",    "thunder",  "ticket",   "tide",     "tiger",    "tilt",
    "timber",   "time",     "tiny",     "tip",      "tired",    "tissue",   "title",    "toast",    "tobacco",
    "today",    "toddler",  "toe",      "together", "toilet",   "token",    "tomato",   "tomorrow", "tone",
    "tongue",   "tonight",  "tool",     "tooth",    "top",      "topic",    "topple",   "torch",    "tornado",
    "tortoise", "toss",     "total",    "tourist",  "toward",   "tower",    "town",     "toy",      "track",
    "trade",    "traffic",  "tragic",   "train",    "transfer", "trap",     "trash",    "travel",   "tray",
    "treat",    "tree",     "trend",    "trial",    "tribe",    "trick",    "trigger",  "trim",     "trip",
    "trophy",   "trouble",  "truck",    "true",     "truly",    "trumpet",  "trust",    "truth",    "try",
    "tube",     "tuition",  "tumble",   "tuna",     "tunnel",   "turkey",   "turn",     "turtle",   "twelve",
    "twenty",   "twice",    "twin",     "twist",    "two",      "type",     "typical",  "ugly",     "umbrella",
    "unable",   "unaware",  "uncle",    "uncover",  "under",    "undo",     "unfair",   "unfold",   "unhappy",
    "uniform",  "unique",   "unit",     "universe", "unknown",  "unlock",   "until",    "unusual",  "unveil",
    "update",   "upgrade",  "uphold",   "upon",     "upper",    "upset",    "urban",    "urge",     "usage",
    "use",      "used",     "useful",   "useless",  "usual",    "utility",  "vacant",   "vacuum",   "vague",
    "valid",    "valley",   "valve",    "van",      "vanish",   "vapor",    "various",  "vast",     "vault",
    "vehicle",  "velvet",   "vendor",   "venture",  "venue",    "verb",     "verify",   "version",  "very",
    "vessel",   "veteran",  "viable",   "vibrant",  "vicious",  "victory",  "video",    "view",     "village",
    "vintage",  "violin",   "virtual",  "virus",    "visa",     "visit",    "visual",   "vital",    "vivid",
    "vocal",    "voice",    "void",     "volcano",  "volume",   "vote",     "voyage",   "wage",     "wagon",
    "wait",     "walk",     "wall",     "walnut",   "want",     "warfare",  "warm",     "warrior",  "wash",
    "wasp",     "waste",    "water",    "wave",     "way",      "wealth",   "weapon",   "wear",     "weasel",
    "weather",  "web",      "wedding",  "weekend",  "weird",    "welcome",  "west",     "wet",      "whale",
    "what",     "wheat",    "wheel",    "when",     "where",    "whip",     "whisper",  "wide",     "width",
    "wife",     "wild",     "will",     "win",      "window",   "wine",     "wing",     "wink",     "winner",
    "winter",   "wire",     "wisdom",   "wise",     "wish",     "witness",  "wolf",     "woman",    "wonder",
    "wood",     "wool",     "word",     "work",     "world",    "worry",    "worth",    "wrap",     "wreck",
    "wrestle",  "wrist",    "write",    "wrong",    "yard",     "year",     "yellow",   "you",      "young",
    "youth",    "zebra",    "zero",     "zone",     "zoo"};

/*
 * This function converts a null terminated hex string
 * to a pointer of unsigned character bytes
 */

unsigned char *hexstr_to_char(const char *hexstr) {

    size_t len = strlen(hexstr);
    size_t final_len = len / 2;

    unsigned char *chrs = (unsigned char *)malloc((final_len + 1) * sizeof(*chrs));

    size_t i, j;

    for (i = 0, j = 0; j < final_len; i += 2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    chrs[final_len] = '\0';

    return chrs;
}

/*
 * This function implements a SHA256 checksum and fills a
 * 64-byte buffer with a fixed-length hex representation of the
 * message digest.
 */

int sha256(char *string, char outputBuffer[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02hhX ", hash[i]);
    }

    outputBuffer[64] = 0;
    return 0;
}

/*
 * This function prints an array of unsigned character bytes
 */

void printUCharArray(unsigned char bytes[], int size) {

    printf("0x");
    char str[size * 2 + 1];

    for (size_t j = 0; j < size; j++) {
        sprintf(&str[j * 2], "%02x", bytes[j]);
    }

    printf("%s\n", str);
}

/*
 * This function prints the mnemonic sentence of size based on the segment
 * size and number of checksum bits appended to the entropy bits.
 */

char *produce_mnemonic_sentence(int segSize, int checksumBits, char *firstByte, char entropy[]) {

    unsigned char *bytes;

    char segment[segSize];
    memset(segment, 0, segSize * sizeof(char));

    char csBits[checksumBits];
    memset(csBits, 0, checksumBits * sizeof(char));

    bytes = hexstr_to_char(firstByte);

    switch (checksumBits) {
        case 5:
            sprintf(csBits, BYTE_TO_FIRST_FOUR_BINARY_PATTERN, BYTE_TO_FIRST_FOUR_BINARY(*bytes));
            break;
        case 6:
            sprintf(csBits, BYTE_TO_FIRST_FIVE_BINARY_PATTERN, BYTE_TO_FIRST_FIVE_BINARY(*bytes));
            break;
        case 7:
            sprintf(csBits, BYTE_TO_FIRST_SIX_BINARY_PATTERN, BYTE_TO_FIRST_SIX_BINARY(*bytes));
            break;
        case 8:
            sprintf(csBits, BYTE_TO_FIRST_SEVEN_BINARY_PATTERN, BYTE_TO_FIRST_SEVEN_BINARY(*bytes));
            break;
        case 9:
            sprintf(csBits, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(*bytes));
            break;
        default:
            exit(EXIT_FAILURE);
            break;
    }

    csBits[checksumBits - 1] = '\0';

    strcat(segment, entropy);
    strcat(segment, csBits);
    segment[segSize - 1] = '\0';

    char elevenBits[12] = {""};
    char *result = malloc(segSize / 11 * (sizeof(char) * 12 + 1)); // Maximum possible size of the result

    if (result == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    int resultIndex = 0;
    int elevenBitIndex = 0;

    for (size_t i = 0; i < segSize; i++) {

        if (elevenBitIndex == 11) {
            elevenBits[11] = '\0';
            long real = strtol(elevenBits, NULL, 2);
            strcat(result, words[real]);
            strcat(result, " ");
            resultIndex += strlen(words[real]) + 1; // Update the resultIndex
            elevenBitIndex = 0;
        }

        elevenBits[elevenBitIndex] = segment[i];
        elevenBitIndex++;
    }

    // Ensure the result is null-terminated.
    result[resultIndex] = '\0';

    return result;
}

/*
 * This function implements the first part of the BIP-39 algorithm.
 * The randomness or entropy for the mnemonic must be a multiple of
 * 32 bits hence the use of 128,160,192,224,256.
 *
 * The CS values below represent a portion (in bits) of the first
 * byte of the checksum or SHA256 digest of the entropy that the user
 * chooses by program option. These checksum bits are added to the
 * entropy prior to splitting the entire random series (ENT+CS) of bits
 * into 11 bit words to be matched with the 2048 count language word
 * file chosen. The final output or mnemonic sentence consists of (MS) words.
 *
 * CS = ENT / 32
 * MS = (ENT + CS) / 11
 *
 * |  ENT  | CS | ENT+CS |  MS  |
 * +-------+----+--------+------+
 * |  128  |  4 |   132  |  12  |
 * |  160  |  5 |   165  |  15  |
 * |  192  |  6 |   198  |  18  |
 * |  224  |  7 |   231  |  21  |
 * |  256  |  8 |   264  |  24  |
 */

char *get_mnemonic(int numWords) { // the only possible numWords are 12, 15, 18, 21, or 24
    int entropysize = (numWords / 3) * 32;

    if (!(entropysize >= 128 && entropysize <= 256 && entropysize % 32 == 0)) {
        fprintf(
            stderr,
            "ERROR: Only the following values for entropy bit sizes may be used: 128, 160, 192, 224, and 256\n");
        exit(EXIT_FAILURE);
    }

    int entBytes = entropysize / 8; // bytes instead of bits
    int csAdd = entropysize / 32;   // portion in bits of a single byte

    /*
     * ENT (Entropy)
     */

    unsigned char entropy[entBytes];
    char entropyBits[entropysize + 1];
    entropyBits[0] = '\0';

    char binaryByte[9];

    /* OpenSSL */
    int rc = RAND_bytes(entropy, sizeof(entropy));

    for (size_t i = 0; i < sizeof(entropy); i++) {
        char buffer[3];
        memcpy(buffer, &entropy[i], 2);
        buffer[2] = '\0';
        unsigned char *byte = hexstr_to_char(buffer);
        sprintf(binaryByte, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(*byte));
        binaryByte[8] = '\0';
        strcat(entropyBits, binaryByte);
    }

    /*
     * ENT SHA256 checksum
     */

    static char checksum[65];
    char entropyStr[sizeof(entropy) * 2 + 1];

    /* me and OpenSSL */
    sha256(entropyStr, checksum);

    char hexStr[3];
    memcpy(hexStr, &checksum[0], 2);
    hexStr[2] = '\0';

    /*
     * CS (Checksum portion) to add to entropy
     */

    return produce_mnemonic_sentence(csAdd * 33 + 1, csAdd + 1, hexStr, entropyBits);
}