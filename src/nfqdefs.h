#ifndef DEFINITIONS_H
#define DEFINITIONS_H
//---------------------------------------------------------------------------

// Defines for main cfg FILE.

#define DEBUG              "DEBUG"
#define INTERFACE          "INTERFACE"
#define REPORTS_DIR        "REPORTS_DIR"
#define POLICIES_DIR       "POLICIES_DIR"
#define CATEGORIES_DIR     "CATEGORIES_DIR"
#define REDIRECTS_FILE     "REDIRECTS_FILE"
#define APPLICATIONS_FILE  "APPLICATIONS_FILE"
#define REDIRECT_ADDRESSES "REDIRECT_ADDRESSES"

// Defines sections for policies files

#define GROUP_INFO         "GROUP_INFO"
#define DEVICES            "DEVICES"
#define BANDWIDTH          "BANDWIDTH"
#define FILTERED           "FILTERED"
#define FIREWALL           "FIREWALL"
#define SAFE_SEARCH        "SAFE_SEARCH"
#define TIME_CONTROL       "TIME_CONTROL"

// defines sections for redirects file

#define FORWARD            "FORWARD"
#define LOCALHOST          "LOCALHOST"
#define BING               "BING"
#define GOOGLE             "GOOGLE"
#define YOUTUBE            "YOUTUBE"

// Defines keys for policies files
#define NAME               "NAME"
#define NAMES              "NAMES"
#define ADDRESSES          "ADDRESSES"
#define ALIAS              "ALIAS"
#define UPLOAD             "UPLOAD"
#define DOWNLOAD           "DOWNLOAD"
#define ALLOW_SITES        "ALLOW_SITES"
#define BLOCK_EXCLUSIVE    "BLOCK_EXCLUSIVE"
#define BLOCK_SITES        "BLOCK_SITES"
#define BLOCK_FILES        "BLOCK_FILES"
#define BLOCK_IPS          "BLOCK_IPS"
#define BLOCK_PORTS_IN     "BLOCK_PORTS_IN"
#define BLOCK_PORTS_OUT    "BLOCK_PORTS_OUT"
#define BLOCK_APPS         "BLOCK_APPS"
#define ENGINES            "ENGINES"
#define MON                "MON"
#define TUE                "TUE"
#define WED                "WED"
#define THU                "THU"
#define FRI                "FRI"
#define SAT                "SAT"
#define SUN                "SUN"

// Defines keys for apps file
#define DOMAINS            "DOMAINS"

// Defines keys for redirects file
#define RESTRICTED_SITE    "RESTRICTED_SITE"
#define SITES              "SITES"

//### Defines for defaults values. ###
// MAIN CONFIG FILE

#define DEF_INTERFACE      "eth0"
#define DEF_MAC_ADDRESS    "00:00:00:00:00:00"
#define DEF_REPORTS_DIR    "/tmp/reports/"
#define DEF_CATEGORIES_DIR "/tmp/filter/categories/"
#define DEF_REDIRECTS_FILE "/tmp/filter/redirects.cfg"
#define DEF_APPS_FILE      "/tmp/filter/applications.cfg"
#define DEF_SAFES_ENGINES  "bing, google"
#define DEF_ALLOWED_SITES  "liveperson.net,saint.mx,saintapp.com,safelearning.mx,saintblu.mx,shield.mx"
#define DEF_CATEGORIES     "alcohol,chats,drugs,gambling,gaming,hacking,p2p,phishing,porn,proxy,tobacco,violence,weapons"

// REDIRECT LOCALHOSTS
#define DEF_LAN            "admin.webfilter.secure"

//---------------------------------------------------------------------------
#endif
