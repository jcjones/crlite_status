import unittest
import status


class TestStructs(unittest.TestCase):
    def test_size_to_str(self):
        self.assertEqual(status.size_to_str("1"), "1 B")
        self.assertEqual(status.size_to_str("4096"), "4.000 kB")
        self.assertEqual(status.size_to_str("7796"), "7.613 kB")
        self.assertEqual(status.size_to_str(1024 * 4.9), "4.899 kB")
        self.assertEqual(status.size_to_str(1024 * 1024 * 11.05), "11.050 MB")
