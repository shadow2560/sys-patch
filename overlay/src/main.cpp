#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#define STBTT_STATIC
#include <tesla.hpp>    // The Tesla Header
#include <string_view>
#include "minIni/minIni.h"

namespace {

constexpr auto CONFIG_PATH = "/config/sys-patch/config.ini";
constexpr auto LOG_PATH = "/config/sys-patch/log.ini";
constexpr auto extra_patches_path = "/config/sys-patch/extra_patches.txt";

/*
#include <stdarg.h>

void debug_log_start() {
	fsdevMountSdmc();
	remove("sdmc:/config/sys-patch/debug.log");
	FILE *debug_log_file;
	debug_log_file = fopen("sdmc:/config/sys-patch/debug.log", "w");
	fclose(debug_log_file);
    fsdevUnmountAll();
}

void debug_log_write(const char *text, ...) {
	fsdevMountSdmc();
	FILE *debug_log_file;
	debug_log_file = fopen("sdmc:/config/sys-patch/debug.log", "a");
	va_list v;
	va_start(v, text);
	vfprintf(debug_log_file, text, v);
	va_end(v);
	fclose(debug_log_file);
    fsdevUnmountAll();
}
*/

char* strdup(const char* str) {
    size_t len = strlen(str) + 1;
    char* copy = (char*)malloc(len);
    if (copy != NULL) {
// strncpy(copy, str, len);
        memcpy(copy, str, len);
    }
    return copy;
}

void trim(char* str) {
	if (str == NULL)
		return;

	char* start = str;
	while (*start && isspace((unsigned char)*start))
		++start;

	size_t len = strlen(start);
	char* end = start + len - 1;
	while (end > start && isspace((unsigned char)*end))
		--end;

	*(end + 1) = '\0';

	if (start != str)
		memmove(str, start, len - (start - str) + 1);
}

char *trim2(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0)  // Chaîne vide
        return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

auto does_file_exist(const char* path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    FsFile file{};
    char path_buf[FS_MAX_PATH]{};

    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strcpy(path_buf, path);
    rc = fsFsOpenFile(&fs, path_buf, FsOpenMode_Read, &file);
    fsFileClose(&file);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

// creates a directory, non-recursive!
auto create_dir(const char* path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    char path_buf[FS_MAX_PATH]{};

    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strcpy(path_buf, path);
    rc = fsFsCreateDirectory(&fs, path_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

struct ConfigEntry {
    ConfigEntry(std::string _section, std::string _key, bool default_value) :
        section{_section}, key{_key}, value{default_value} {
            this->load_value_from_ini();
        }

    void load_value_from_ini() {
        this->value = ini_getbool(this->section.c_str(), this->key.c_str(), this->value, CONFIG_PATH);
    }

    auto create_list_item(const char* text) {
        auto item = new tsl::elm::ToggleListItem(text, value);
        item->setStateChangedListener([this](bool new_value){
            this->value = new_value;
            ini_putl(this->section.c_str(), this->key.c_str(), this->value, CONFIG_PATH);
        });
        return item;
    }

    std::string const section;
    std::string const key;
    bool value;
};

class GuiOptions final : public tsl::Gui {
public:
    GuiOptions() { }

    tsl::elm::Element* createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        list->addItem(new tsl::elm::CategoryHeader("Options"));
        list->addItem(config_patch_sysmmc.create_list_item("Patch sysMMC"));
        list->addItem(config_patch_emummc.create_list_item("Patch emuMMC"));
        list->addItem(config_logging.create_list_item("Logging"));
        list->addItem(config_version_skip.create_list_item("Version skip"));
        list->addItem(config_clean_config.create_list_item("Clean config file"));
        list->addItem(config_load_extra_patches.create_list_item("Load extra patches file"));
        frame->setContent(list);
        return frame;
    }

    ConfigEntry config_patch_sysmmc{"options", "patch_sysmmc", true};
    ConfigEntry config_patch_emummc{"options", "patch_emummc", true};
    ConfigEntry config_logging{"options", "enable_logging", true};
    ConfigEntry config_version_skip{"options", "version_skip", true};
    ConfigEntry config_clean_config{"options", "clean_config", true};
    ConfigEntry config_load_extra_patches{"options", "load_extra_patches", true};
};

class GuiToggle final : public tsl::Gui {
public:
GuiToggle() { }
/*
    GuiToggle() {
        // Initialisation des configurations organisées par catégories
        configEntries = {
            {["fs", "fs - 0100000000000000"], {
                {"fs", "noacidsigchk_1", true},
                {"fs", "noacidsigchk_2", true},
                {"fs", "noncasigchk_1", true},
                {"fs", "noncasigchk_2", true},
                {"fs", "noncasigchk_3", true},
                {"fs", "nocntchk_1", true},
                {"fs", "nocntchk_2", true},
            }},
            {["ldr", "ldr - 0100000000000001"], {
                {"ldr", "noacidsigchk", true},
                {"ldr", "debug_flag", false},
                {"ldr", "debug_flag_off", false},
            }},
            {["es", "es - 0100000000000033"], {
                {"es", "es_1", true},
                {"es", "es_2", true},
                {"es", "es_3", true},
                {"es", "es_4", true},
            }},
            {["nifm", "nifm - 010000000000000F"], {
                {"nifm", "ctest", true},
                {"nifm", "ctest_2", true},
                {"nifm", "ctest_3", true},
            }},
            {["nim", "nim - 0100000000000025"], {
                {"nim", "fix_prodinfo_blank_error", true},
                {"nim", "fix_prodinfo_blank_error_2", true},
            }},
            {["ssl", "Disable CA Verification - apply all"], {
                {"ssl", "disablecaverification_1", false},
                {"ssl", "disablecaverification_2", false},
                {"ssl", "disablecaverification_3", false},
            }},
            {["erpt", "erpt - 010000000000002b"], {
                {"erpt", "no_erpt", false},
            }},
        };
    }
*/

    tsl::elm::Element* createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        if (config_load_extra_patches.value == true) {
            load_extra_patches_configs(extra_patches_path);
        }

        if (configEntries.empty()) {
            list->addItem(new tsl::elm::ListItem("No patches found!"));
        } else {
            for (const auto& [categoryKey, entries] : configEntries) {
                addCategoryToList(list, categoryKey[1], categoryKey[0]);
            }
        }

        frame->setContent(list);
        return frame;
    }

    ConfigEntry config_load_extra_patches{"options", "load_extra_patches", true};

    void addCategory(const std::string& categoryName, const std::string& description) {
        const auto it = std::find_if(configEntries.begin(), configEntries.end(), [&categoryName](const auto& pair) { return pair.first[0] == categoryName; });
        if (it != configEntries.end()) {
            return;
        }
    configEntries.push_back({{categoryName, description}, {}});
    }

    bool addConfigEntry(const std::string categoryName, const ConfigEntry newEntry) {
        auto it = std::find_if(configEntries.begin(), configEntries.end(), [&categoryName](const auto& pair) { return pair.first[0] == categoryName; });
        if (it == configEntries.end()) {
            return false;
        }

        for (const auto& entry : it->second) {
            if (entry.key == newEntry.key) {
                return false;
            }
        }

        it->second.push_back(newEntry);
        return true;
    }

private:
    std::list<std::pair<std::array<std::string, 2>, std::list<ConfigEntry>>> configEntries;

    void addCategoryToList(tsl::elm::List* list, const std::string& categoryHeader, const std::string& categoryName) {
        auto it = std::find_if(configEntries.begin(), configEntries.end(), [&categoryName](const auto& pair) { return pair.first[0] == categoryName; });
        if (it == configEntries.end() || it->second.empty()) {
            return;
        }
        list->addItem(new tsl::elm::CategoryHeader(categoryHeader.c_str()));
        for (auto& entry : it->second) {
            list->addItem(entry.create_list_item(entry.key.c_str()));
        }
    }

    bool load_extra_patches_configs(const char* filename) {
        NxFile file;
        bool rc=ini_openread(filename, &file);
        if (!rc) {
            return false;
        }

        char line[256];
        char *actual_section = {};
        char *trimmed_line = {};
        size_t buffer_length=sizeof(line);
        size_t line_trim_alloc = buffer_length + 1;
        bool first_line_init = false;
        int count_buff_line_passed = 0;
    int z = 0;
        while (ini_read2(line, buffer_length, &file)) {
            if (!first_line_init) {
                trimmed_line = (char*) calloc(1, line_trim_alloc);
                first_line_init = true;
            }
            strcat(trimmed_line, line);
            if ((trimmed_line[strlen(trimmed_line) - 1] != '\r' && trimmed_line[strlen(trimmed_line) - 1] != '\n') && strlen(trimmed_line) > 0) {
                z++;
                if (z > count_buff_line_passed) {
                    line_trim_alloc += buffer_length;
                    trimmed_line = (char*) realloc(trimmed_line, line_trim_alloc);
                    count_buff_line_passed++;
                }
                continue;
            }
            z = 0;
            trim(trimmed_line);
            if (trimmed_line[0] == '\0' || trimmed_line[0] == ';' || trimmed_line[0] == '\r' || trimmed_line[0] == '\n') {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }

            if (trimmed_line[0] == '[' && trimmed_line[strlen(trimmed_line) - 1] == ']') {
                trimmed_line[strlen(trimmed_line) - 1] = '\0';
                if (actual_section) {
                    free(actual_section);
                }
                actual_section = strdup(trimmed_line + 1);
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }

            if (!actual_section) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }

            char patch_name[50];
            char* token;

            if (strcmp(actual_section, "patches_entries") == 0) {
char titleid[19], category_desc[70];
                token = strtok(trimmed_line, ",");
                if (token != nullptr) {
                    strncpy(patch_name, trim2(token), sizeof(patch_name) - 1);
                } else {
                    memset(trimmed_line, '\0', line_trim_alloc);
                    continue;
                }
                token = strtok(nullptr, ",");
                if (token != nullptr) {
                    strncpy(titleid, trim2(token), sizeof(titleid) - 1);
                } else {
                    memset(trimmed_line, '\0', line_trim_alloc);
                    continue;
                }
                token = strtok(nullptr, ",");
                if (token != nullptr) {
                    strncpy(category_desc, trim2(token), sizeof(category_desc) - 1);
                } else {
                    memset(trimmed_line, '\0', line_trim_alloc);
                    continue;
                }
                if (strcmp(category_desc, "") == 0) {
                    (std::string) category_desc = (std::string) patch_name + " - " + (std::string) titleid;
                }
                addCategory((std::string) patch_name, (std::string) category_desc);
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }

            int enabled = 0;

            token = strtok(trimmed_line, ",");
            if (token != nullptr) {
                strncpy(patch_name, trim2(token), sizeof(patch_name) - 1);
            } else {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token == nullptr) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token == nullptr) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token == nullptr) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token == nullptr) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token == nullptr) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token == nullptr) {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }
            token = strtok(nullptr, ",");
            if (token != nullptr) {
                enabled = atoi(trim2(token));
            } else {
                memset(trimmed_line, '\0', line_trim_alloc);
                continue;
            }

            ConfigEntry new_config = ConfigEntry(
                (std::string) actual_section,
                (std::string) patch_name,
                (bool)enabled
            );

            addConfigEntry((std::string) actual_section, new_config);
            memset(trimmed_line, '\0', line_trim_alloc);
        }

        ini_close(&file);
        if (trimmed_line) {
            free(trimmed_line);
        }
        if (actual_section) {
            free(actual_section);
        }
        return true;
    }

};

class GuiLog final : public tsl::Gui {
public:
    GuiLog() { }

    tsl::elm::Element* createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        if (does_file_exist(LOG_PATH)) {
            struct CallbackUser {
                tsl::elm::List* list;
                std::string last_section;
            } callback_userdata{list};

            ini_browse([](const mTCHAR *Section, const mTCHAR *Key, const mTCHAR *Value, void *UserData){
                auto user = (CallbackUser*)UserData;
                std::string_view value{Value};

                if (value == "Skipped") {
                    return 1;
                }

                if (user->last_section != Section) {
                    user->last_section = Section;
                    user->list->addItem(new tsl::elm::CategoryHeader("Log: " + user->last_section));
                }

                #define F(x) ((x) >> 4) // 8bit -> 4bit
                constexpr tsl::Color colour_syspatch{F(0), F(255), F(200), F(255)};
                constexpr tsl::Color colour_file{F(255), F(177), F(66), F(255)};
                constexpr tsl::Color colour_unpatched{F(250), F(90), F(58), F(255)};
                #undef F

                if (value.starts_with("Patched")) {
                    if (value.ends_with("(sys-patch)")) {
                        user->list->addItem(new tsl::elm::ListItem(Key, "Patched", colour_syspatch));
                    } else {
                        user->list->addItem(new tsl::elm::ListItem(Key, "Patched", colour_file));
                    }
                } else if (value.starts_with("Unpatched") || value.starts_with("Disabled")) {
                    user->list->addItem(new tsl::elm::ListItem(Key, Value, colour_unpatched));
                } else if (user->last_section == "stats") {
                    user->list->addItem(new tsl::elm::ListItem(Key, Value, tsl::style::color::ColorDescription));
                } else {
                    user->list->addItem(new tsl::elm::ListItem(Key, Value, tsl::style::color::ColorText));
                }

                return 1;
            }, &callback_userdata, LOG_PATH);
        } else {
            list->addItem(new tsl::elm::ListItem("No log found!"));
        }

        frame->setContent(list);
        return frame;
    }
};

class GuiMain final : public tsl::Gui {
public:
    GuiMain() { }

    tsl::elm::Element* createUI() override {
        auto frame = new tsl::elm::OverlayFrame("sys-patch", VERSION_WITH_HASH);
        auto list = new tsl::elm::List();

        auto options = new tsl::elm::ListItem("Options");
        auto toggle = new tsl::elm::ListItem("Toggle patches");
        auto log = new tsl::elm::ListItem("Log");

        options->setClickListener([](u64 keys) -> bool {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<GuiOptions>();
                return true;
            }
            return false;
        });

        toggle->setClickListener([](u64 keys) -> bool {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<GuiToggle>();
                return true;
            }
            return false;
        });

        log->setClickListener([](u64 keys) -> bool {
            if (keys & HidNpadButton_A) {
                tsl::changeTo<GuiLog>();
                return true;
            }
            return false;
        });

        list->addItem(new tsl::elm::CategoryHeader("Menu"));
        list->addItem(options);
        list->addItem(toggle);
        list->addItem(log);

        frame->setContent(list);
        return frame;
    }
};

// libtesla already initialized fs, hid, pl, pmdmnt, hid:sys and set:sys
class SysPatchOverlay final : public tsl::Overlay {
public:
    std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<GuiMain>();
    }
};

} // namespace

int main(int argc, char **argv) {
    create_dir("/config/");
    create_dir("/config/sys-patch/");
    return tsl::loop<SysPatchOverlay>(argc, argv);
}
