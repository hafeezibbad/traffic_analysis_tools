import os
import unittest

from core.lib.file_utils import search_file, get_unique_filename, has_valid_extension, get_filename_and_ext
from tests.fixtures.common import FIXTURES_DIRECTORY_PATH


class FileUtilsTest(unittest.TestCase):
    def test_search_file_returns_none_if_directory_is_none(self):
        self.assertIsNone(search_file(directory=None, filename='filename.ext'))

    def test_search_file_returns_none_if_filename_is_none(self):
        self.assertIsNone(search_file(directory='/path/to/folder', filename=None))

    def test_search_file_returns_none_if_file_not_found_in_directory(self):
        self.assertIsNone(search_file(directory=FIXTURES_DIRECTORY_PATH, filename='filename.ext'))

    def test_search_file_returns_absolute_path_if_file_is_found(self):
        file_path = search_file(directory=FIXTURES_DIRECTORY_PATH, filename='common.py')
        self.assertIsNotNone(file_path)
        self.assertEqual(os.path.join(FIXTURES_DIRECTORY_PATH, 'common.py'), file_path)

    def test_get_unique_filename_returns_none_if_directory_is_none(self):
        self.assertIsNone(get_unique_filename(directory=None, filename='filename.ext'))

    def test_get_unique_filename_returns_none_if_directory_is_empty(self):
        self.assertIsNone(get_unique_filename(directory='', filename='filename.ext'))

    def test_get_unique_filename_returns_none_if_directory_does_not_exist(self):
        self.assertIsNone(get_unique_filename(directory='/non/existing/folder', filename='filename.ext'))

    def test_get_unique_filename_returns_none_if_filename_is_none(self):
        self.assertIsNone(get_unique_filename(directory=FIXTURES_DIRECTORY_PATH, filename=None))

    def test_get_unique_filename_returns_none_if_filename_is_empty(self):
        self.assertIsNone(get_unique_filename(directory=FIXTURES_DIRECTORY_PATH, filename=''))

    def test_get_unique_filename_returns_unique_filename(self):
        unique_filename = get_unique_filename(directory=FIXTURES_DIRECTORY_PATH, filename='filename.ext')
        self.assertIsNotNone(unique_filename)
        self.assertEqual(os.path.join(FIXTURES_DIRECTORY_PATH, 'filename-001.ext'), unique_filename)

    def test_has_valid_extension_return_false_if_no_extension_specified(self):
        self.assertFalse(has_valid_extension(
            file_path=os.path.join(FIXTURES_DIRECTORY_PATH, 'common.py'),
            valid_extensions=None)
        )

    def test_has_valid_extension_return_false_if_empty_extension_specified(self):
        self.assertFalse(has_valid_extension(
            file_path=os.path.join(FIXTURES_DIRECTORY_PATH, 'common.py'),
            valid_extensions=[])
        )

    def test_has_valid_extension_return_false_if_specified_extension_is_not_list(self):
        for extension in ['extensions', 1234, dict(extension='py')]:
            self.assertFalse(has_valid_extension(
                file_path=os.path.join(FIXTURES_DIRECTORY_PATH, 'common.py'),
                valid_extensions=extension)
            )

    def test_has_valid_extension_accepts_list_set_and_tuple_for_extension_argument(self):
        for extension in [['py'], {'py'}, ('py',)]:
            print(extension)
            self.assertTrue(has_valid_extension(
                file_path=os.path.join(FIXTURES_DIRECTORY_PATH, 'common.py'),
                valid_extensions=extension)
            )

    def test_get_filename_and_ext_returns_none_if_file_path_is_None(self):
        filename, ext = get_filename_and_ext(file_path=None)
        self.assertIsNone(filename)
        self.assertIsNone(ext)

    def test_get_filename_and_ext_returns_none_if_file_path_is_empty(self):
        filename, ext = get_filename_and_ext(file_path='')
        self.assertIsNone(filename)
        self.assertIsNone(ext)

    def test_get_filename_and_ext_returns_only_filename_if_filename_has_no_extension(self):
        filename, ext = get_filename_and_ext(
            file_path=os.path.abspath(os.path.join(FIXTURES_DIRECTORY_PATH, 'filename'))
        )
        self.assertEqual('filename', filename)
        self.assertIsNone(ext)

    def test_get_filename_and_ext_returns_both_filename_and_ext(self):
        filename, ext = get_filename_and_ext(
            file_path=os.path.abspath(os.path.join(FIXTURES_DIRECTORY_PATH, 'filename.ext'))
        )
        self.assertEqual('filename.ext', filename)
        self.assertEqual('ext', ext)
