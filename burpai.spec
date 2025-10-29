# -*- mode: python ; coding: utf-8 -*-
# ruff: noqa: F821, UP009
# pyright: reportUndefinedVariable=false

from pathlib import Path
import shutil
import os
import tempfile
import re
import atexit
from src.utils import logger, init_logger


def get_config():
    def str_to_bool(value):
        return value.lower() in ("1", "true")

    return {
        "llm_url": os.environ.get("LLM_URL"),
        "onedir_mode": str_to_bool(os.environ.get("ONEDIR", "false")),
    }


def setup_build_directory():
    build_dir = Path(tempfile.mkdtemp(prefix="burpai-build-"))

    def cleanup():
        if build_dir.exists():
            shutil.rmtree(build_dir)
            logger.info("Cleaned up build directory")

    atexit.register(cleanup)
    return build_dir


def copy_source_tree(build_dir):
    src_dir = Path(SPECPATH) / "src"
    shutil.copytree(src_dir, build_dir / "src", dirs_exist_ok=True)
    logger.info("Copied source to build directory: %s", build_dir)


def replace_llm_url(build_dir, llm_url):
    if not llm_url:
        return

    settings_py_path = build_dir / "src" / "settings.py"
    content = settings_py_path.read_text()
    content = re.sub(
        r'("llm_url".*?"default":\s*)"http://localhost:11434/v1"',
        rf'\1"{llm_url}"',
        content,
        flags=re.DOTALL,
    )
    settings_py_path.write_text(content)
    logger.info("Replaced default llm_url with: %s", llm_url)


def prepare_build():
    config = get_config()
    build_dir = setup_build_directory()
    copy_source_tree(build_dir)
    replace_llm_url(build_dir, config["llm_url"])

    prompts_dir = build_dir / "src" / "prompts"
    data_files = [(str(prompts_dir), "src/prompts")]

    return build_dir, data_files, config


def create_analysis(build_dir, data_files):
    main_py = build_dir / "src" / "main.py"
    return Analysis(
        [str(main_py)],
        pathex=[str(build_dir)],
        binaries=[],
        datas=data_files,
        hiddenimports=[
            "keyring.backends.kwallet",
            "keyring.backends.SecretService",
            "keyring.backends.Windows",
            "keyring.backends.macOS",
            "keyring.backends.libsecret",
            "dbus",
            "secretstorage",
        ],
        hookspath=[],
        hooksconfig={},
        runtime_hooks=[],
        excludes=[
            "tkinter",
            "sqlite3",
            "unittest",
            "doctest",
            "pydoc",
            "setuptools",
        ],
        noarchive=False,
        optimize=1,
    )


def build_executable(archive, analysis, onedir_mode):
    exe_kwargs = {
        "name": "burpai",
        "debug": False,
        "bootloader_ignore_signals": False,
        "strip": True,
        "console": True,
        "disable_windowed_traceback": False,
    }

    if onedir_mode:
        exe = EXE(
            archive,
            analysis.scripts,
            [],
            exclude_binaries=True,
            **exe_kwargs,
        )

        collection = COLLECT(
            exe,
            analysis.binaries,
            analysis.datas,
            strip=False,
            upx=True,
            upx_exclude=[],
            name="burpai",
        )
        return exe, collection
    exe = EXE(
        archive,
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        upx=True,
        upx_exclude=[],
        **exe_kwargs,
    )
    return exe, None


def main():
    init_logger()
    build_dir, data_files, config = prepare_build()
    analysis = create_analysis(build_dir, data_files)
    archive = PYZ(analysis.pure)
    build_executable(archive, analysis, config["onedir_mode"])


main()
