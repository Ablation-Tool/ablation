import importlib
import importlib.metadata
import tomllib
from pathlib import Path
from unittest.mock import patch

import ablation
import ablation.export.sarif as sarif


def test_sarif_uses_package_distribution_name():
    with patch('importlib.metadata.version', return_value='2.88.0') as version:
        reloaded = importlib.reload(sarif)
        assert reloaded._VERSION == '2.88.0'
        version.assert_called_once_with('ablation-tool')
    importlib.reload(sarif)


def test_project_version_matches_runtime_version():
    config = tomllib.loads(Path('pyproject.toml').read_text())
    assert config['project']['version'] == ablation.__version__


def test_bytecode_extra_and_package_resources_are_declared():
    config = tomllib.loads(Path('pyproject.toml').read_text())
    extras = config['project']['optional-dependencies']
    assert 'xdis>=6.0' in extras['bytecode']
    assert 'lz4>=4.0' in extras['bytecode']
    assert 'xdis>=6.0' in extras['full']
    assert 'lz4>=4.0' in extras['full']

    package_data = config['tool']['setuptools']['package-data']
    assert '*.md' in package_data['ablation.data']
    assert 'profiles/*.yaml' in package_data['ablation']
