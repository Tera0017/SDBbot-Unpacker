"""
Author:@Tera0017
SDBbot static unpacker
"""
from sdbbot_unpacker_scripts.sdbbot_rat import SDBbotRatx86, SDBbotRatx64
from sdbbot_unpacker_scripts.sdbbot_loader import SDBbotLoaderx86, SDBbotLoaderx64
from sdbbot_unpacker_scripts.sdbbot_regblob import SDBbotRegBlobx86, SDBbotRegBlobx64
from sdbbot_unpacker_scripts.sdbbot_installer import SDBbotInstallerx86, SDBbotInstallerx64
from sdbbot_unpacker_scripts.sdbbot_gen_funcs import get_osa, gen_name, message, writeFile, process_args, ERROR01


class SDBbotUnpacker:

    def __init__(self, arguments):
        self.filepath = arguments.file
        self.osa = get_osa(file_path=self.filepath)

    def unpack(self):
        Installer, Loader, RegBlob, Rat = {
            0x32: (SDBbotInstallerx86, SDBbotLoaderx86, SDBbotRegBlobx86, SDBbotRatx86),
            0x64: (SDBbotInstallerx64, SDBbotLoaderx64, SDBbotRegBlobx64, SDBbotRatx64),
        }[self.osa]
        # Installer module
        sdbbot_installer = Installer(self.filepath)
        data = sdbbot_installer.decode()
        installer_filepath = gen_name(self.filepath, 'SDBbot_SdbInstallerDll_')
        writeFile(installer_filepath, data)
        message('SdbInstallerDll successfully dumped: {}'.format(installer_filepath))

        # Loader module
        sdbbot_loader = Loader(installer_filepath)
        data = sdbbot_loader.decode()
        loader_filepath = gen_name(self.filepath, 'SDBbot_RegCodeLoader_')
        writeFile(loader_filepath, data)
        message('RegCodeLoader successfully dumped: {}'.format(loader_filepath))

        # Registry Blob
        sdbbot_regblob = RegBlob(installer_filepath)
        data = sdbbot_regblob.decode()
        regblob_filepath = gen_name(self.filepath, 'SDBbot_RegBlob_')
        writeFile(regblob_filepath, data)
        message('RegBlob successfully dumped: {}'.format(regblob_filepath))

        # RAT module
        sdbbot_rat = Rat(installer_filepath)
        data = sdbbot_rat.decode()
        rat_filepath = gen_name(self.filepath, 'SDBbot_RAT_BotDLL_')
        writeFile(rat_filepath, data)
        message('BotDLL successfully dumped: {}'.format(rat_filepath))

        return True


if __name__ == '__main__':
    sdbbot_unpacker = SDBbotUnpacker(process_args())
    try:
        sdbbot_unpacker.unpack()
    except Exception:
        message(ERROR01)
