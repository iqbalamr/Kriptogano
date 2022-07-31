"""
KriptoGano

[Tujuan]
KriptoGano adalah sebuah alat steganografi yang dikembangkan untuk memenuhi
Tugas Besar kami di mata kuliah Kriptografi di Institut Teknologi Sumatera
KriptoGano berasal dari singkatan Kriptografi dan Steganografi.

[Authors]
Iqbal Amrulloh - Principle Developer
Bintang Yosafat - Contributor - Developer
Nafis - Contributor - Developer

[Fungsionalitas]
KriptoGano bekerja dengan menghasikan data AES yang terenkripsi dari secret message
dan secret key. Selanjutnya menghasilkan bilangan biner acak yang memiliki jumlah 
digit yang cukup sehingga setiap piksel dalam gambar dipetakan ke angka biner. 
Kemudian program akan menyandikan data ke dalam bentuk bit terkecil (LSB), setiap
piksel hanya dikodekan dalam nilai RGB tertentu, yang dilanjutkan ke encoding pada
data yang terenkripsi.

"""


from PIL import Image
from bitstring import BitArray
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import init
from termcolor import colored

import sys
import hashlib
import random
import time


# termcolors activation
init()

def check_extension(fileName):
    extension = fileName[-4:].lower()

    if (extension != '.png'):
        print()
        print(
            colored(
                "Invalid file type -- Images must be in PNG format. Try again!",
                'red'))
        print()
        return 1
    else:
        return 0


def check_file(fileName):
    extenCheck = check_extension(fileName)

    # Failed extension check
    if (extenCheck == 1):
        return 1

    # Check if available -- if not, then return 1
    try:
        fileObject = open(fileName, "r")
        fileObject.close()
        return 0
    except IOError:
        print()
        print(colored("Invalid file path. Try again!", 'red'))
        print()
        return 1
    
def check_image_size(fileName, secretMsg, encryptionKey):
    imageWorker = Image.open(fileName)

    backend = default_backend()  # Default backend for the AES

    key = bytearray()  # Create a byte array to store the
    key.extend(map(ord, encryptionKey))

    shaAlgo = hashlib.sha256()
    shaAlgo.update(key)

    keyHexString = shaAlgo.hexdigest()

    secretMsgBytes = secretMsg.encode()

    # Split hash into initVector and AES key
    initVectorHex = keyHexString[0:32]
    keyHex = keyHexString[32:64]
    initVec = bytes.fromhex(initVectorHex)
    keyBytes = bytes.fromhex(keyHex)

    # Create the encryption cipher -- AES256.CFB -- no padding required
    AESCipher = Cipher(algorithms.AES(keyBytes),
                       modes.CFB(initVec),
                       backend=backend)
    encryptor = AESCipher.encryptor()
    cipherText = encryptor.update(secretMsgBytes)
    cipherBits = BitArray(bytes=cipherText).bin
    cipherBitsLength = len(cipherBits)

    totalEncodablePixels = (imageWorker.size[0] *
                            imageWorker.size[1]) - imageWorker.size[0]

    if ((totalEncodablePixels * 3) < cipherBitsLength):
        print()
        print(colored("The image is too small. Try again!", 'red'))
        print()
        return 1
    else:
        return 0

def decimal_to_binary(n):
    return bin(n).replace("0b", "")


def bitstring_to_bytes(s):
    # return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))

def show_banner():
    print(colored(("KriptoGano"), 'green'))
    print(colored("by Iqbal and others.", "red"))
    print()

def main_menu():
    print(
        colored("===================== Menu ============================", 'cyan'))
    print()
    print(colored("1) Hide a secret message into an image", 'yellow'))
    print(colored("2) Find a secret message from an image", 'yellow'))
    print(colored("3) Exit KriptoGano", 'yellow'))
    print()

def hide_menu():
    print(
        colored("Select a specific functionality from the menu below", 'cyan'))
    print()
    print(colored("1) Hide a raw string", 'yellow'))
    #print(colored("2) Hide a single file, or multiple files", 'yellow'))
    print(colored("2) Go back", 'yellow'))
    print()

def raw_text_input():
    # These are flags to check for invalid or no input
    secretMessageInputCheck = False
    secretKeyInputCheck = False
    srcImageInputCheck = 1
    dstImageInputCheck = False

    print()

    # Get the SECRET MESSAGE
    while (secretMessageInputCheck == False):
        encodeInputMsg = input("Enter a SECRET MESSAGE to hide -> ")

        if (encodeInputMsg != ""):
            secretMessageInputCheck = True
        else:
            print()
            print(
                colored(
                    "You need to provide a SECRET MESSAGE to hide. Try again!",
                    'red'))
            print()

    # Get the SECRET KEY
    while (secretKeyInputCheck == False):
        encodeInputKey = input(
            "Enter a SECRET KEY to encrypt the secret message -> ")

        if (encodeInputKey != ""):
            secretKeyInputCheck = True
        else:
            print()
            print(
                colored("You need to provide a SECRET KEY. Try again!", 'red'))
            print()

    # Check for valid source image
    while (srcImageInputCheck == 1):
        encodeSrcImgPath = input("Provide the PATH of the source image -> ")

        # Replace the spaces in the file path -- at either end and in between
        encodeSrcImgPath = encodeSrcImgPath.replace(" ", "")

        # Check if image exists
        srcImageInputCheck = check_file(encodeSrcImgPath)

        # Valid file name
        if (srcImageInputCheck == 0):
            # Check if the image is big enough
            srcImageInputCheck = check_image_size(encodeSrcImgPath,
                                                  encodeInputMsg,
                                                  encodeInputKey)

    # Check for destination image name
    while (dstImageInputCheck == False):
        encodeDstImgName = input("Provide the NAME for the encoded image -> ")

        # Replace the spaces in the file path -- at either end and in between
        encodeDstImgName = encodeDstImgName.replace(" ", "")

        dstImageFileNameCheck = check_extension(encodeDstImgName)

        # Valid file name
        if (encodeDstImgName != "" and dstImageFileNameCheck == 0):
            dstImageInputCheck = True
        else:
            print()
            print(
                colored(
                    "You need to provide a name and extension (e.g. test.png) for the destination image",
                    'red'))
            print()

    print()

    return encodeInputKey, encodeInputMsg, encodeSrcImgPath, encodeDstImgName

def find_input():
    print()

    decodeInputKey = input(
        "Enter the SECRET KEY that was used to encrypt the secret message -> ")

    # Check if the source image exists
    # Use the same input check, set it to 1
    srcImageInputCheck = 1

    while (srcImageInputCheck == 1):
        decodeSrcImgPath = input("Provide the PATH of the source image -> ")

        # Replace the spaces in the file path -- at either end and in between
        decodeSrcImgPath = decodeSrcImgPath.replace(" ", "")

        # Check if image exists
        srcImageInputCheck = check_file(decodeSrcImgPath)

    print()

    return decodeInputKey, decodeSrcImgPath

def find(decryptionKey, srcImgFile):

    # decodeProg = InitBar()
    # prog = InitBar(title = "Finding...", size = 100, offset = 4, )


    # Get the preliminary stuff
    backend = default_backend()
    key = bytearray()
    key.extend(map(ord, decryptionKey))

    shaAlgo = hashlib.sha256()
    shaAlgo.update(key)

    keyHexString = shaAlgo.hexdigest()

    initVectorHex = keyHexString[0:32]
    keyHex = keyHexString[32:64]

    # Create the byte arrays of the init vector and the AES key -- 128 bits each
    initVec = bytes.fromhex(initVectorHex)
    keyBytes = bytes.fromhex(keyHex)

    # Create the decryptor
    AESCipher = Cipher(algorithms.AES(keyBytes),
                       modes.CFB(initVec),
                       backend=backend)
    decryptor = AESCipher.decryptor()

    # Open the image and load the pixels
    imageWorker = Image.open(srcImgFile)
    pixelManipulator = imageWorker.load()

    # This will hold the length of the cipher text in binary string
    cipherTextLength = ""
 
    # This is the counter length of the cipher, this will tell the decryptor when to stop
    # Going through the image
    for row in range(1):
        for col in range(10):
            # Get the binary RGB values
            binary_r = decimal_to_binary(
                pixelManipulator[col, row][0]).zfill(8)
            binary_g = decimal_to_binary(
                pixelManipulator[col, row][1]).zfill(8)
            binary_b = decimal_to_binary(
                pixelManipulator[col, row][2]).zfill(8)

            # Get the last digit of the binary RGB value
            binary_r_last_digit = binary_r[7]
            binary_g_last_digit = binary_g[7]
            binary_b_last_digit = binary_b[7]

            cipherTextLength += binary_r_last_digit + \
                binary_g_last_digit + binary_b_last_digit

    
    #########################################################################################################
    #########################################################################################################

    # Convert the cipher text length from binary to decimal
    messageLength = int(cipherTextLength, 2)

    # Create the random number
    # Get the total encodable length --> Size in bits of the random number
    totalPixels = imageWorker.size[0] * imageWorker.size[1]

    # Total encodable length = all pixels - row 0
    totalEncodableLen = totalPixels - imageWorker.size[0]

    random.seed(keyHexString)

    big_rand_bin = decimal_to_binary(random.getrandbits(totalEncodableLen))

    # Padding to make the random number the correct size, if needed
    while (len(big_rand_bin) != totalEncodableLen):
        # print("INCORRECT LENGTH GENERATED - FIXING IT")
        big_rand_bin += str(len(big_rand_bin) % 2)

    # Get the cipher string -- binary
    # This is going to be the 0's and 1's from the image
    cipherTextString = ""

    row = 1
    col = 0
    cipherTextIterator = 0
    randomNumberIterator = 0
    decodeCount = 0
    sub = messageLength % 3

    while (row < imageWorker.size[1] and cipherTextIterator < messageLength):
        while (col < imageWorker.size[0]
               and cipherTextIterator < messageLength):
            # indexLoc = cipherTextIterator % 3

            if (cipherTextIterator < messageLength - sub
                    and randomNumberIterator < totalEncodableLen):
                # If the random number[index] == 1, then there is data encoded
                if (str(big_rand_bin)[randomNumberIterator] == "1"):
                    # Get the R, G, or B value - based on the modulo calculation
                    binaryDigit_r = pixelManipulator[col, row][0]
                    binaryDigit_g = pixelManipulator[col, row][1]
                    binaryDigit_b = pixelManipulator[col, row][2]

                    # Turn the R, G, or B value into binary
                    binaryDigit_r = decimal_to_binary(binaryDigit_r).zfill(8)
                    binaryDigit_g = decimal_to_binary(binaryDigit_g).zfill(8)
                    binaryDigit_b = decimal_to_binary(binaryDigit_b).zfill(8)

                    cipherTextString += binaryDigit_r[7]
                    cipherTextString += binaryDigit_g[7]
                    cipherTextString += binaryDigit_b[7]

                    decodeCount += 3
                    cipherTextIterator += 3
            elif (sub == 1 and randomNumberIterator < totalEncodableLen):
                if (str(big_rand_bin)[randomNumberIterator] == "1"):
                    binaryDigit_r = pixelManipulator[col, row][0]
                    binaryDigit_r = decimal_to_binary(binaryDigit_r).zfill(8)
                    cipherTextString += binaryDigit_r[7]

                    decodeCount += 1
                    cipherTextIterator += 1
            elif (sub == 2 and randomNumberIterator < totalEncodableLen):
                if (str(big_rand_bin)[randomNumberIterator] == "1"):
                    binaryDigit_r = pixelManipulator[col, row][0]
                    binaryDigit_r = decimal_to_binary(binaryDigit_r).zfill(8)
                    cipherTextString += binaryDigit_r[7]

                    binaryDigit_g = pixelManipulator[col, row][1]
                    binaryDigit_g = decimal_to_binary(binaryDigit_g).zfill(8)
                    cipherTextString += binaryDigit_g[7]

                    decodeCount += 2
                    cipherTextIterator += 2

            col += 1
            randomNumberIterator += 1

        col = 0
        row += 1
     

    print("\n")

    cipherBytes = bitstring_to_bytes(cipherTextString)


    print()
    try:
        plainText = decryptor.update(cipherBytes)

        plainText = plainText.decode("utf-8")

        print(
            "\u001b[36;1m=====================================================================\u001b[0m"
            )
        print(colored("HIDDEN MESSAGE: " + str(plainText), 'green'))
        print(
            "\u001b[36;1m=====================================================================\u001b[0m"
            )
    except:
            print()
            print(
                colored("Error retrieving data from the image. Try again!",
                        'red'))
            print()



def hide(encryptionKey, secretMsg, srcImgFile, dstImgFile):

    backend = default_backend()  # Default backend for the AES Cipher creator

    key = bytearray()  # Create a byte array to store the
    key.extend(map(ord, encryptionKey))

    shaAlgo = hashlib.sha256()
    shaAlgo.update(key)

    keyHexString = shaAlgo.hexdigest()
    secretMsgBytes = secretMsg.encode()
    
    # Converts the initialization vector to bits
    # Always 128 bits -- os.urandom(16) => 16 bytes = 128 bits

    # Split hash into initVector and AES key
    initVectorHex = keyHexString[0:32]
    keyHex = keyHexString[32:64]

    initVec = bytes.fromhex(initVectorHex)
    keyBytes = bytes.fromhex(keyHex)

    # Create the encryption cipher -- AES256.CFB -- no padding required
    AESCipher = Cipher(algorithms.AES(keyBytes),
                       modes.CFB(initVec),
                       backend=backend)
    encryptor = AESCipher.encryptor()

    cipherText = encryptor.update(secretMsgBytes)

    # This is going to be encoded into the actual image
    cipherBits = BitArray(bytes=cipherText).bin

    # Get the length of the cipher bits
    # The [2:] at the end chops off the 0b part of 0b1000 for example
    # The zfill 30 will make the 1000 (8) for example into
    # 00000000000000000000000001000 so we can just write
    # from the left to write
    cipherBitsLengthBinary = bin(len(cipherBits))[2:].zfill(30)

    imageWorker = Image.open(srcImgFile)

    # Gets all the pixels of the image
    pixelManipulator = imageWorker.load()

    # Total # of pixels in  the image = length * height
    totalPixels = imageWorker.size[0] * imageWorker.size[1]

    # Total encodable length = all pixel after the 1st row
    # The first row is sectioned off
    totalEncodableLen = totalPixels - imageWorker.size[0]

    # Write the header

    # This is to iterate over the 30 bit cipher length while it is being written into the header
    cipherLenIterator = 0

    # Encode the cipher binary length into the header pixels -- 10 pixels
    for row in range(1):
        for col in range(10):
            # pixelManipulator[0] = 8-bit r value
            # pixelManipulator[1] = 8-bit g value
            # pixelManipulator[2] = 8-bit b value

            binary_r = decimal_to_binary(
                pixelManipulator[col, row][0]).zfill(8)
            binary_g = decimal_to_binary(
                pixelManipulator[col, row][1]).zfill(8)
            binary_b = decimal_to_binary(
                pixelManipulator[col, row][2]).zfill(8)

            binary_r = binary_r[:7] + cipherBitsLengthBinary[cipherLenIterator]
            binary_g = binary_g[:7] + cipherBitsLengthBinary[cipherLenIterator
                                                             + 1]
            binary_b = binary_b[:7] + cipherBitsLengthBinary[cipherLenIterator
                                                             + 2]

            # Converts from binary to int
            encoded_r = int(binary_r, 2)
            encoded_g = int(binary_g, 2)
            encoded_b = int(binary_b, 2)

            # Get the bit values of the pixel and change them

            # This will write each RBG (0-2) value in pixels 0-9 with 1 bit of the cipherBitsLengthBinary string
            pixelManipulator[col, row] = (encoded_r, encoded_g, encoded_b)
            cipherLenIterator += 3
###################################################################################################################
    # Time to encode the AES encrypted data turned into a cipher into the RGB values
    # 1) Create a random number with the seed
    # Start at the second row -- row 2, pixel 0

    # Generate a random number with totalEncodableLen amount of bits that is seeded
    random.seed(keyHexString)

    # Creates a random seeded number that has is the size of the total encodable length
    # This is a behemoth of a number -- absolute unit
    big_rand_bin = random.getrandbits(totalEncodableLen)

    big_rand_bin = bin(big_rand_bin)[2:]

    # If the random number isn't long enough, this will pad it with 0's and 1's until
    # it reaches the correct length
    while (len(big_rand_bin) != totalEncodableLen):
        big_rand_bin += str(len(big_rand_bin) % 2)

    # Iterators
    cipherTextIterator = 0  # Iterates through the cipher text
    randomNumIterator = 0  # Iterates through the random number
    sizeOfCipher = len(cipherBits)  # Size of the cipher

    row = 1
    col = 0

    encodedCount = 0
    sub = sizeOfCipher % 3
    while (row < imageWorker.size[1] and cipherTextIterator < sizeOfCipher):
        while (col < imageWorker.size[0]
               and cipherTextIterator < sizeOfCipher):
            # indexLoc = cipherTextIterator % 3

            if (cipherTextIterator < sizeOfCipher - sub
                    and randomNumIterator < totalEncodableLen):

                if (str(big_rand_bin)[randomNumIterator] == "1"):
                    # 0b10101010
                    binaryDigit_r = pixelManipulator[col, row][0]
                    binaryDigit_g = pixelManipulator[col, row][1]
                    binaryDigit_b = pixelManipulator[col, row][2]

                    # 0b10101010 -> 10101010
                    binaryDigit_r = bin(binaryDigit_r)[2:].zfill(8)
                    binaryDigit_g = bin(binaryDigit_g)[2:].zfill(8)
                    binaryDigit_b = bin(binaryDigit_b)[2:].zfill(8)

                    # 1010101 -> 1010101[cipher_bit]
                    encodedBinaryDigit_r = binaryDigit_r[:7] + str(
                        cipherBits)[cipherTextIterator]
                    encodedBinaryDigit_g = binaryDigit_g[:7] + str(cipherBits)[
                        cipherTextIterator + 1]
                    encodedBinaryDigit_b = binaryDigit_b[:7] + str(cipherBits)[
                        cipherTextIterator + 2]

                    # 10101011 -> 171
                    encodedDecimal_r = int(encodedBinaryDigit_r, 2)
                    encodedDecimal_g = int(encodedBinaryDigit_g, 2)
                    encodedDecimal_b = int(encodedBinaryDigit_b, 2)

                    # R, G, B -> New R, G, B
                    pixelManipulator[col, row] = (encodedDecimal_r,
                                                  encodedDecimal_g,
                                                  encodedDecimal_b)

                    encodedCount += 3
                    cipherTextIterator += 3
            elif (sub == 1 and randomNumIterator < totalEncodableLen):
                if (str(big_rand_bin)[randomNumIterator] == "1"):
                    binaryDigit_r = pixelManipulator[col, row][0]
                    binaryDigit_r = bin(binaryDigit_r)[2:].zfill(8)
                    encodedBinaryDigit_r = binaryDigit_r[:7] + str(
                        cipherBits)[cipherTextIterator]
                    encodedDecimal_r = int(encodedBinaryDigit_r, 2)
                    pixelManipulator[col, row] = (
                        encodedDecimal_r, pixelManipulator[col, row][1],
                        pixelManipulator[col, row][2])

                    encodedCount += 1
                    cipherTextIterator += 1
            elif (sub == 2 and randomNumIterator < totalEncodableLen):
                if (str(big_rand_bin)[randomNumIterator] == "1"):
                    binaryDigit_r = pixelManipulator[col, row][0]
                    binaryDigit_r = bin(binaryDigit_r)[2:].zfill(8)
                    encodedBinaryDigit_r = binaryDigit_r[:7] + str(
                        cipherBits)[cipherTextIterator]
                    encodedDecimal_r = int(encodedBinaryDigit_r, 2)

                    binaryDigit_g = pixelManipulator[col, row][1]
                    binaryDigit_g = bin(binaryDigit_g)[2:].zfill(8)
                    encodedBinaryDigit_g = binaryDigit_g[:7] + str(cipherBits)[
                        cipherTextIterator + 1]
                    encodedDecimal_g = int(encodedBinaryDigit_g, 2)
                    pixelManipulator[col, row] = (
                        encodedDecimal_r, encodedDecimal_g,
                        pixelManipulator[col, row][2])

                    encodedCount += 2
                    cipherTextIterator += 2

            col += 1
            randomNumIterator += 1

        col = 0
        row += 1

        # progBar = cipherTextIterator / sizeOfCipher
        # progBar = progBar * 100
        # prog(progBar)

    
    print()

    # Save the image as the requested file name
    imageWorker.save(dstImgFile)

    print()
    print(
         "\u001b[36;1m=====================================================================\u001b[0m"
    )
    print(
        colored(
            "DONE -- MODIFIED image saved to current directory as: " +
            dstImgFile + "", 'green'))
    print(
         "\u001b[36;1m=====================================================================\u001b[0m"
    )
    print()




def main():
    userMenuInput = 0
    hideMenuInput = 0

    show_banner()

    while (userMenuInput != 3):
        main_menu()

        try:
            userMenuInput = int(input("Menu option selection -> "))
            userMenuInput = int(userMenuInput)

            if (userMenuInput == 3):  # Option 3 --> Quit
                print()
                print(
                    colored(
                        "Thank you for using KriptoGano",
                        'green'))
                print()
                sys.exit(0)

            elif (userMenuInput == 1):  # Option 2 --> Hide a message

                # Resetting this back to 0 because if a user quits and comes back,
                # They will immediately quit because they had quit before (hideMenuInput = 3)
                # and it wasn't reset so it's still 3
                hideMenuInput = 0

                while (hideMenuInput != 3):

                    hide_menu()  # 1) Raw String, Files, or Back to Main Menu

                    try:
                        hideMenuInput = input("Menu option selection -> ")
                        hideMenuInput = int(hideMenuInput)

                        if (hideMenuInput == 3):
                            print()
                            print(
                                colored("Going back to the main menu.",
                                        'yellow'))
                            print()
                        elif (hideMenuInput == 1):  # Option 1 --> Raw String
                            encodeInputKey, encodeInputMsg, encodeSrcImgPath, encodeDstImgName = raw_text_input(
                            )

                            print(colored("Encoding...", "green"))
                            print()

                            startTime = time.time()

                            hide(encodeInputKey, encodeInputMsg,
                                 encodeSrcImgPath, encodeDstImgName)
                            
                            endTime = time.time()

                            print(
                                colored(
                                    "Total execution time: " +
                                    str(endTime - startTime) + " seconds",
                                    'magenta'))    
                            print()

                            hideMenuInput = 3
                        

                    except ValueError:
                        print()
                        print(colored("Invalid Input. Try again.", 'red'))
                        print()

            elif (userMenuInput == 2):  # Option 3 --> Find a message
                decodeInputKey, decodeSrcImgPath = find_input()

                startTime = time.time()
                print(colored("Decoding...", "green"))
                print()
                find(decodeInputKey, decodeSrcImgPath)
                print()

                endTime = time.time()

                print(
                    colored(
                        "Total execution time: " + str(endTime - startTime) +
                        " seconds", 'magenta'))
                print()
        except ValueError:
            print()
            print(colored("Invalid Input. Try again.", 'red'))
            print()
    print()


if __name__ == "__main__":
    main()