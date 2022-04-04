# -*- coding:utf-8 -*-

"""
作者: plusman
日期: 2022/04/02
"""

import base64
import binascii
import gzip
import hashlib
import json
import sys
import urllib.parse

import pyperclip
from PyQt5.QtWidgets import QApplication, QMainWindow

from ui import MainWindow


class ChangeTool(QMainWindow, MainWindow.Ui_MainWindow):
    def __init__(self):
        super(ChangeTool, self).__init__()
        self.setupUi(self)
        self.clear_all.clicked.connect(self.btn_clear_all_clicked)
        self.copy_all.clicked.connect(self.btn_copy_all_clicked)
        self.hex_to_str.clicked.connect(self.btn_hex2str_clicked)
        self.get_md5.clicked.connect(self.btn_get_md5_clicked)
        self.str_to_hex.clicked.connect(self.btn_str2hex_clicked)
        self.get_sha1.clicked.connect(self.btn_get_sha1_clicked)
        self.gzip_compress.clicked.connect(self.btn_gzip_compress_clicked)
        self.gzip_uncompress.clicked.connect(self.btn_gzip_uncompress_clicked)
        self.bytes_reversal.clicked.connect(self.btn_bytes_reversal_clicked)
        self.int_to_hex.clicked.connect(self.btn_int2hex_clicked)
        self.hex_to_base64.clicked.connect(self.btn_hex2base64_clicked)
        self.base64_to_hex.clicked.connect(self.btn_base642hex_clicked)
        self.json_format.clicked.connect(self.btn_json_format_clicked)
        self.json_compress.clicked.connect(self.btn_json_compress_clicked)
        self.int2hex_big.clicked.connect(self.btn_int2hex_big_clicked)
        self.int2hex_little.clicked.connect(self.btn_int2hex_little_clicked)
        self.get_hex_len.clicked.connect(self.btn_get_hex_len_clicked)
        self.url_decode.clicked.connect(self.btn_url_decode_clicked)
        self.url_encode.clicked.connect(self.btn_url_encode_clicked)
        self.hex_to_int.clicked.connect(self.btn_hex2int_clicked)

    def btn_clear_all_clicked(self):
        self.input_text.clear()
        self.output_text.clear()
        self.statusbar.setToolTip('操作完成!')

    def btn_copy_all_clicked(self):
        text = self.output_text.toPlainText()
        if text:
            pyperclip.copy(text)
            # print(text)

    def btn_hex2str_clicked(self):
        hex_str = self.input_text.toPlainText()
        if hex_str:
            try:
                out_str = binascii.unhexlify(hex_str).decode('utf-8')
                self.output_text.setText(out_str)
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_str2hex_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            self.output_text.setText(text.encode('utf-8').hex())

    def btn_hex2int_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                self.output_text.setText(str(int.from_bytes(binascii.unhexlify(text), byteorder='little')))
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_get_md5_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            self.output_text.setText(hashlib.md5(
                text.encode('utf-8')).hexdigest())

    def btn_get_sha1_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            self.output_text.setText(hashlib.sha1(
                text.encode('utf-8')).hexdigest())

    def btn_gzip_compress_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                gzip_data = gzip.compress(text.encode('utf-8'))
                self.output_text.setText(gzip_data.hex())
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_gzip_uncompress_clicked(self):
        try:
            bytes_array = self.input_text.toPlainText()
            bytes_array = binascii.unhexlify(bytes_array)
            text = gzip.decompress(bytes_array)
            self.output_text.setText(text.decode('utf-8'))
        except BaseException:
            self.output_text.setText('原始数据错误')

    def btn_bytes_reversal_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                bytes_array = binascii.unhexlify(text)
                bytes_array = bytes_array[::-1]
                self.output_text.setText(bytes_array.hex())
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_int2hex_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                int_byte = int(text).to_bytes(length=4, byteorder='little')
                self.output_text.setText(int_byte.hex())
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_hex2base64_clicked(self):
        try:
            hex_str = self.input_text.toPlainText()
            base64_str = base64.b64encode(binascii.unhexlify(hex_str))
            self.output_text.setText(base64_str.decode('utf-8'))
        except BaseException:
            self.output_text.setText('原始数据错误')

    def btn_base642hex_clicked(self):
        try:
            base64_str = self.input_text.toPlainText()
            text = base64.b64decode(base64_str)
            self.output_text.setText(text.hex())
        except BaseException:
            self.output_text.setText('原始数据错误')

    def btn_json_format_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                text = json.loads(text)
                text = json.dumps(text, indent=4, ensure_ascii=False)
                self.output_text.setText(text)
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_json_compress_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                text = json.loads(text)
                text = json.dumps(text, ensure_ascii=False)
                self.output_text.setText(text)
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_int2hex_big_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                int_byte = int(text).to_bytes(length=4, byteorder='big')
                self.output_text.setText(int_byte.hex())
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_int2hex_little_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                int_byte = int(text).to_bytes(length=4, byteorder='little')
                self.output_text.setText(int_byte.hex())
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_get_hex_len_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            try:
                len_str = str(len(binascii.unhexlify(text)))
                self.output_text.setText(len_str)
            except BaseException:
                self.output_text.setText('原始数据错误')

    def btn_url_encode_clicked(self):
        text = self.input_text.toPlainText()
        if text:
            text = urllib.parse.quote(text.encode('utf-8'))
            self.output_text.setText(text)

    def btn_url_decode_clicked(self):
        """

        :return:
        """
        text = self.input_text.toPlainText()
        if text:
            text = urllib.parse.unquote(text, encoding='utf-8')
            self.output_text.setText(text)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = ChangeTool()
    ui.show()
    sys.exit(app.exec_())
