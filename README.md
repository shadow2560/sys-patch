# sys-patch

A script-like system module that patches **fs**, **es**, **ldr**, **nifm** and **nim** on boot.

---

## Config

**sys-patch** features a simple config. This can be manually edited or updated using the overlay.

The configuration file can be found in `/config/sys-patch/config.ini`. The file is generated once the module is ran for the first time.

```ini
[options]
patch_sysmmc=1   ; 1=(default) patch sysmmc, 0=don't patch sysmmc
patch_emummc=1   ; 1=(default) patch emummc, 0=don't patch emummc
enable_logging=1 ; 1=(default) output /config/sys-patch/log.ini 0=no log
version_skip=1   ; 1=(default) skips out of date patterns, 0=search all patterns
clean_config=1 ; 1=(default) clean the config file (if load_extra_patches is set to 0 (disabled in the overlay) it will clean the extra_patches configs also), 0=don't clean the config file
load_extra_patches=1   ; 1=(default) load extra patches and extra patches entries in "/config/sys-patch/extra_patches.txt", 0=don't load extra patches
```

The file "extra_patches.txt" is build like that:
```
; General rules:
; Keep a blank line at the end of the file
; Don't use special chars, use only "A-Z", "a-z", "0-9", "_", "-", "." and " "
; Use the "," char only to separate fields
; Prefer to set every fields, even if firmware versions or Atmosphere version is not always required because set to "FW_VER_ANY" by default it's preferable to set them
; Fields are always trimmed

; Patches entries rules:
; section "patches_entries" is reserved to declare only patches entries and must be the first section of the file
; ; One line by patches_entry
; Name of the patch entry can't be more than 49 chars and must match an other section of this file or a category used in source code
; The third field is used to describe the patches entry in the overlay (69 chars max), if not present the patches entry will be concidered invalid and if empty the description will be "patches_entry_name - patches_entry_titleid"
; Firmware version needs to be declared like that: 2.0.0 or 19.0.1 or FW_VER_ANY (this one is to tell that no firmware version is limited for that value of the patch entry)
; Other rules are the same as original sys-patch patches entries declaration

; Patterns rules:
; One line by pattern
; Name of the pattern can't be more than 49 chars
; Hex pattern can't be more than 127 chars (the "0x" witch could start the value are counted in them)
; Firmware version or Atmosphere version need to be declared like that: 1.8.0 or 19.0.1 or FW_VER_ANY (this one is to tell that no firmware version is limited for that value of the pattern)
; To enable pattern replace "true" by "1" and "false" by "0"
; sections name for a patterns list must refer to a category, in the source code or in the "extra_patches_entries" section
; Other rules are the same as original sys-patch patterns declaration and list of functions witch can be used are in the source code

[patches_entries]
fs, 0x0100000000000000, fs - 0100000000000000, FW_VER_ANY, FW_VER_ANY
ldr, 0x0100000000000001, ldr - 0100000000000001, 10.0.0, FW_VER_ANY
es, 0x0100000000000033, es - 0100000000000033,, 2.0.0, FW_VER_ANY
nifm, 0x010000000000000F, nifm - 010000000000000F, FW_VER_ANY, FW_VER_ANY
nim, 0x0100000000000025, nim - 0100000000000025, FW_VER_ANY, FW_VER_ANY
ssl, 0x0100000000000024, Disable CA Verification - apply all, FW_VER_ANY, FW_VER_ANY
erpt, 0x010000000000002b, erpt - 010000000000002b, 10.0.0, FW_VER_ANY
[fs]
noacidsigchk_1, 0xC8FE4739, -24, 0, bl_cond, ret0_patch, ret0_applied, 1, FW_VER_ANY, 9.2.0, FW_VER_ANY, FW_VER_ANY
noacidsigchk_2, 0x0210911F000072, -5, 0, bl_cond, ret0_patch, ret0_applied, 1, FW_VER_ANY, 9.2.0, FW_VER_ANY, FW_VER_ANY
noncasigchk_1, 0x0036.......71..0054..4839, -2, 0, tbz_cond, nop_patch, nop_applied, 1, 10.0.0, 16.1.0, FW_VER_ANY, FW_VER_ANY
noncasigchk_2, 0x.94..0036.258052, 2, 0, tbz_cond, nop_patch, nop_applied, 1, 17.0.0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
nocntchk_1, 0x40f9...9408.0012.050071, 2, 0, bl_cond, ret0_patch, ret0_applied, 1, 10.0.0, 18.1.0, FW_VER_ANY, FW_VER_ANY
nocntchk_2, 0x40f9...94..40b9..0012, 2, 0, bl_cond, ret0_patch, ret0_applied, 1, 19.0.0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
[ldr]
noacidsigchk, 0xFD7B.A8C0035FD6, 16, 2, subs_cond, subs_patch, subs_applied, 1, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
debug_flag_on, 0x6022403900010035, -4, 0, no_cond, debug_flag_patch, debug_flag_applied, 0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
debug_flag_off, 0x6022403900010035, -4, 0, no_cond, debug_flag_off_patch, debug_flag_off_applied, 0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
[es]
es_1, 0x..00.....e0.0091..0094..4092...d1, 16, 0, and_cond, mov0_patch, mov0_applied, 1, FW_VER_ANY, 1.0.0, FW_VER_ANY, FW_VER_ANY
es_2, 0x..00.....e0.0091..0094..4092...a9, 16, 0, and_cond, mov0_patch, mov0_applied, 1, 2.0.0, 8.1.1, FW_VER_ANY, FW_VER_ANY
es_3, 0x..00...0094a0..d1..ff97.......a9, 16, 0, mov2_cond, mov0_patch, mov0_applied, 1, 9.0.0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
[nifm]
ctest, 0x....................F40300AA....F30314AAE00314AA9F0201397F8E04F8, 16, -16, ctest_cond, ctest_patch, ctest_applied, 1, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
[nim]
fix_prodinfo_blank_error, 0x.0F00351F2003D5, 8, 0, adr_cond, mov2_patch, mov2_applied, 1, 17.0.0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
[ssl]
disablecaverification_1, 0x6A0080D2, 0, 0, mov3_cond, ssl1_patch, ssl1_applied, 0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
disablecaverification_2, 0x2409437AA0000054, 4, 0, beq_cond, ret1_patch, ret1_applied, 0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
disablecaverification_3, 0x88160012, 4, 0, str_cond, ssl2_patch, ssl2_applied, 0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY
[erpt]
no_erpt, 0xFD7B02A9FD830091F76305A9, -4, 0, no_cond, erpt_patch, erpt_applied, 0, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY, FW_VER_ANY

```

---

## Overlay

The overlay can be used to change the config options and to see what patches are applied.

- Unpatched means the patch wasn't applied (likely not found).
- Patched (green) means it was patched by sys-patch.
- Patched (yellow) means it was already patched, likely by sigpatches or a custom Atmosphere build.

<p float="left">
  <img src="https://i.imgur.com/yDhTdI6.jpg" width="400" />
  <img src="https://i.imgur.com/G6U9wGa.jpg" width="400" />
  <img src="https://i.imgur.com/cSXUIWS.jpg" width="400" />
  <img src="https://i.imgur.com/XNLWLqL.jpg" width="400" />
</p>

---

## Building

### prerequisites
- Install [devkitpro](https://devkitpro.org/wiki/Getting_Started)
- Run the following:
  ```sh
  git clone --recurse-submodules https://github.com/ITotalJustice/sys-patch.git
  cd ./sys-patch
  make
  ```

The output of `out/` can be copied to your SD card.
To activate the sys-module, reboot your switch, or, use [sysmodules overlay](https://github.com/WerWolv/ovl-sysmodules/releases/latest) with the accompanying overlay to activate it.

---

## What is being patched?

Here's a quick run down of what's being patched:

- **fs** and **es** need new patches after every new firmware version.
- **ldr** needs new patches after every new [Atmosphere](https://github.com/Atmosphere-NX/Atmosphere/) release. For "debug_flag_on" and "debug_flag_off" patches prefer to rebuild your forwarders than using these patches witch can cause some problems.
- **nifm** ctest patch allows the device to connect to a network without needing to make a connection to a server
- **nim** patches to the ssl function call within nim that queries "https://api.hac.%.ctest.srv.nintendo.net/v1/time", and crashes the console if console ssl certificate is not intact. This patch instead makes the console not crash.
- **ssl** patches to disable the SSL verification in browser, enable it if you realy need it.
- **erpt** patches to disable ERPT writes from Atmosphere, enable it if you realy need it.

The patches are applied on boot. Once done, the sys-module stops running.
The memory footprint *(13kib)* and the binary size *(~60kib)* are both very small.

---

## FAQ:

### If I am using sigpatches already, is there any point in using this?

Yes, in 3 situations.

1. A new **ldr** patch needs to be created after every Atmosphere update. Sometimes, a new silent Atmosphere update is released. This tool will always patch **ldr** without having to update patches.

2. Building Atmosphere from src will require you to generate a new **ldr** patch for that custom built Atmosphere. This is easy enough due to the public scripts / tools that exist out there, however this will always be able to patch **ldr**.

3.  If you forget to update your patches when you update your firmware / Atmosphere, this sys-module should be able to patch everything. So it can be used as a fall back.

### Does this mean that I should stop downloading / using sigpatches?

No, I would personally recommend continuing to use sigpatches. Reason being is that should this tool ever break, i likely wont be quick to fix it.

---

## Credits / Thanks

Software is built on the shoulders of giants. This tool wouldn't be possible without these people:

- MrDude
- BornToHonk (farni)
- TeJay
- ArchBox
- Switchbrew (libnx, switch-examples)
- DevkitPro (toolchain)
- [minIni](https://github.com/compuphase/minIni)
- [libtesla](https://github.com/WerWolv/libtesla)
- [Shoutout to the best switch cfw setup guide](https://rentry.org/SwitchHackingIsEasy)
- N
