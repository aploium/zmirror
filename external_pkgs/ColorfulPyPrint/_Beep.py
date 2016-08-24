# Generate a beep when called.
def beep():
    import sys
    # A stock AMIGA 1200 using Python 1.4 or greater.
    # This assumes that the sound is enabled in the PREFS: drawer.
    # AND/OR the screen flash is enabled also.
    if sys.platform == 'amiga':
        print('\a\v')
    # MS Windows (TM), from Windows ME upwards. Used in Command
    # Prompt mode for best effect.
    # The *.WAV file can be anything of your choice.
    # CHORD.WAV was the default.
    # SNDREC32.EXE no longer exists in WIndows Vista, and higher?
    if sys.platform == 'win32':
        from winsound import Beep
        Beep(770, 1000)
        # os.system('SNDREC32.EXE "C:\WINDOWS\MEDIA\CHORD.WAV" /EMBEDDING /PLAY /CLOSE')
        # print(chr(7))
    # A generic error beep for all Linux platforms.
    # There is a simple way to change the frequency, and the amplitude.
    # This also works in a Linux terminal running a Python interpreter!
    if 'linux' in sys.platform:
        audio = open('/dev/audio', 'wb')
        count = 0
        while count < 250:
            beep = chr(63) + chr(63) + chr(63) + chr(63)
            audio.write(beep)
            beep = chr(0) + chr(0) + chr(0) + chr(0)
            audio.write(beep)
            count = count + 1
        audio.close()
        # Add here for other OSs.
        # Add here any peculiarities.
        # if sys.platform=='some-platform':
        # Do some sound error beep.
