"""GApplication uses Gio, while network requests use Python's TLS stack."""

from PyInstaller.utils.hooks.gi import GiModuleInfo


def hook(hook_api):
    module_info = GiModuleInfo("Gio", "2.0")
    if module_info.available:
        binaries, datas, hiddenimports = module_info.collect_typelib_data()
        hook_api.add_binaries(binaries)
        hook_api.add_datas(datas)
        hook_api.add_imports(*hiddenimports)
