"""
Author:@Tera0017
Extracts Installer module
"""
from sdbbot_decoder import SDBbotDecoderx86, SDBbotDecoderx64


class SDBbotInstaller:

    def __init__(self, filepath, osa):
        self.filepath = filepath
        self.osa = osa

    def decode(self):
        Decoder = {
            0x32: SDBbotDecoderx86,
            0x64: SDBbotDecoderx64,
        }[self.osa]

        sdbinstaller_decoder = Decoder(self.filepath)
        return sdbinstaller_decoder.decode()


class SDBbotInstallerx86(SDBbotInstaller):

    def __init__(self, filepath):
        SDBbotInstaller.__init__(self, filepath, 0x32)


class SDBbotInstallerx64(SDBbotInstaller):

    def __init__(self, filepath):
        SDBbotInstaller.__init__(self, filepath, 0x64)
