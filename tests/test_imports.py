from malleus.cli import app
from malleus.datasets import dataset_root


def test_imports_work():
    assert app is not None
    assert dataset_root().name == 'datasets'
