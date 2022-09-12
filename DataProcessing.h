// DataProcessing.h : Functions for processing and transforming data.

#include "stdafx.h"

using namespace System;
using namespace System::Collections;
using namespace System::IO;

///Converts hex string to bytes, assuming input is Big Endian. 
array<Byte>^ hexToBytes(String ^ hexIn)
{
	//Remove spaces in hex input to prevent processing errors.
	hexIn = hexIn->Replace(" ", "");

	//How many bytes are needed (a byte takes up two hex digits)?
	int bytesNeeded;
	if(hexIn->Length % 2 == 1) //For processing ease, make hex input an even number of digits
	{
		hexIn = "0" + hexIn;
	}
	bytesNeeded = hexIn->Length / 2;

	//Resulting bytes to return.
	array<Byte>^ result = gcnew array<Byte>(bytesNeeded);

	//Going through bytes to fill them with appropriate hex values.
	for(int onByte = 0; onByte < bytesNeeded; onByte++)
	{
		result[onByte] = int::Parse(hexIn->Substring(onByte * 2, 2),
					Globalization::NumberStyles::HexNumber);
	}

	//Return resulting bytes.
	return result;
}

///Converts integer to byte array.
array<Byte> ^ intToBytes(int inputInt)
{
	//Will hold bytes to return.
	array<Byte> ^ bytesToReturn = gcnew array<Byte>(4);

	//Goes through all four bytes.
	for(int onByte = 0; onByte < 4; onByte++)
	{
		//How input integer will affect current byte
		int forThisByte = inputInt / Math::Pow(256, 3 - onByte);
		bytesToReturn[onByte] = (Byte)forThisByte;

		//How much of integer has been dealt with
		inputInt -= forThisByte * Math::Pow(256, 3 - onByte);
	}

	//Returns the final array of bytes for the input int.
	return bytesToReturn;
}


///Converts stream of bytes to hex string.
String ^ bytesToHex(array<Byte> ^ bytesIn)
{
	//Will hold resulting hex string.
	String ^ hexHolder = "";

	//Going through each byte.
	for(int onByte = 0; onByte < bytesIn->Length; onByte++)
	{
		//For each byte, finding greater and smaller hex digit.
		int upperDigit = (int)bytesIn[onByte] / 16;
		int lowerDigit = (int)(int)bytesIn[onByte] % 16;

		//Adding upper digit to final hex string.
		switch(upperDigit)
		{
		case 10:
			hexHolder += "A";
			break;
		case 11:
			hexHolder += "B";
			break;
		case 12:
			hexHolder += "C";
			break;
		case 13:
			hexHolder += "D";
			break;
		case 14:
			hexHolder += "E";
			break;
		case 15:
			hexHolder += "F";
			break;
		default:
			hexHolder += upperDigit.ToString();
			break;
		}

		//Adding lower digit to final hex string.  Adding space to separate it from
		//a possible next hex digit pair.
		switch(lowerDigit)
		{
		case 10:
			hexHolder += "A ";
			break;
		case 11:
			hexHolder += "B ";
			break;
		case 12:
			hexHolder += "C ";
			break;
		case 13:
			hexHolder += "D ";
			break;
		case 14:
			hexHolder += "E ";
			break;
		case 15:
			hexHolder += "F ";
			break;
		default:
			hexHolder += lowerDigit.ToString() + " ";
			break;
		}
	}

	//Return hex results.
	return hexHolder;
}

///Converts ascii string to bytes, assuming input is left-to-right.
array<Byte>^ asciiToBytes(String ^ asciiIn)
{
	//Converting input to char array.
	array<Char>^ inputToChars = asciiIn->ToCharArray();

	//Converting char array to byte array.
	array<Byte>^ inputBytes = gcnew array<Byte>(asciiIn->Length);
	for(int onByte = 0; onByte < asciiIn->Length; onByte++)
	{
		inputBytes[onByte] = (Byte)inputToChars[onByte];
	}

	//Return input bytes, once appropriately updated.
	return inputBytes;
}

///Does right shift (>>) of 1 on bit array inputted.
BitArray ^ DoRightShift(BitArray ^ input)
{
	//Will hold shifted bit set.
	BitArray ^ newBits = gcnew BitArray(input->Length);

	//Fill new bit set with shifted input.
	for(int onBit = 1; onBit < newBits->Length; onBit++)
	{
		newBits[onBit] = input[onBit - 1];
	}

	//Left most bit will be 0 if shifting.
	newBits->default[0] = false;

	//Return shifted ("new") bit set.
	return newBits;
}

///Flips the endianness of each individual byte.
BitArray ^ FlipBytesEndian(BitArray ^ input)
{
	//Go through each bit.
	for(int onBit = 0; onBit < input->Length; onBit++)
	{
		//Put a bit in its opposite position in byte.
		if(onBit % 8 < 4)
		{
			int temp = input[onBit];
			input[onBit] = input[onBit / 8 * 8 + 7 - onBit % 8];
			input[onBit / 8 * 8 + 7 - onBit % 8] = temp;
		}
	}

	//Returns input with bit positions flipped.
	return input;
}

///Gets MD5 hash of file inputted.  Then, returns the hash and then file size.
array<String^> ^ doMd5Hash(String ^ fileIn)
{
	//Find size of file inputted.
	IO::FileInfo ^ fileInfo = gcnew IO::FileInfo(fileIn);

	//Will hold bytes of input file.
	Byte * bytesIn = new Byte[fileInfo->Length];

	//Starts to read file.
	FileStream ^ fin = gcnew FileStream(fileIn, FileMode::Open);
				 
	//Read file's bytes until end of file.
	for(int onByte = 0; onByte < fileInfo->Length; onByte++)
	{
		//If byte cannot be read, end of file is likely reached.
		try
		{
			Byte theByte = (Byte)fin->ReadByte();
			bytesIn[onByte] = theByte;
		}
		catch(System::Exception ^ex)
		{
			Console::WriteLine("\r\n->" + ex->Message);
			break;
		}
	}

	/*Convert byte array to format MD5 encrypter needs.  Using incrementer from previous loop
	that read bytes.*/
	array<Byte> ^staticBytes = gcnew array<Byte>(fileInfo->Length);
	for(int onByte = 0; onByte < fileInfo->Length; onByte++)
	{
		staticBytes[onByte] = bytesIn[onByte];
	}

	//Encrypt the file's bytes.
	System::Security::Cryptography::MD5 ^md5Encrypter = System::Security::Cryptography::MD5::Create();
	array<Byte> ^encryptedBytes = md5Encrypter->ComputeHash(staticBytes);
	//array<Byte> ^testBytes = gcnew array<Byte>(sizeof(bytesIn));
	//array<Byte> ^encryptedBytes = md5Encrypter->ComputeHash(testBytes);

	//Returns MD5 result and file size.
	array<String^> ^ theResult = gcnew array<String^>(2);
	theResult[0] = bytesToHex(encryptedBytes);
	theResult[1] = fileInfo->Length.ToString();
	return theResult;
}

///Performs a single 8-cycle algorithmic procedure.
BitArray ^ Do8CycleProcedure(BitArray ^ inputIn, BitArray ^ feedbackIn)
{
	//Performing algorithm on inputs (run through procedure 8 times).
	for(int onIter = 1; onIter <= 8; onIter++)
	{
		if(inputIn[inputIn->Length - 1] == 0) //If last bit is 0
		{
			//Right shift on bits
			inputIn = DoRightShift(inputIn);
		}
		else //If last bit is 1
		{
			//Right shift on bits
			inputIn = DoRightShift(inputIn);

			//Xoring key creation progress bits with "initial value" input.
			inputIn = inputIn->Xor(feedbackIn);
		}
	}

	//Returns input after it has been appropriately modified.
	return inputIn;
}

///Putting encrypter function (for Challenge 1) in its proper form.
unsigned char *Crypt(unsigned char *data, int dataLength, unsigned int initialValue) {
	//Set up initial value, data byte, feedback byte, and encryption result arrays.
	array<Byte>^ initValueBytes = gcnew array<Byte>(dataLength);
	array<Byte>^ dataBytes = gcnew array<Byte>(dataLength);
	array<Byte>^ feedbackBytes = hexToBytes("87654321");
	array<Byte>^ encryptionResult = gcnew array<Byte>(dataLength);

	//Converting initial value int to bytes.
	initValueBytes = intToBytes(initialValue);

	//Converting data input to bytes.
	for(int onDataChar = 0; onDataChar < dataLength; onDataChar++)
	{
		dataBytes[onDataChar] = (Byte)data[onDataChar];
	}
				 
	//Converting init value bytes, data input bytes, and feedback bytes to bits.
	//Then, making bits Big Endian.
	BitArray ^ initValueBits = gcnew BitArray(initValueBytes);
	BitArray ^ dataBits = gcnew BitArray(dataBytes);
	BitArray ^ feedbackBits = gcnew BitArray(feedbackBytes);
	initValueBits = FlipBytesEndian(initValueBits);
	dataBits = FlipBytesEndian(dataBits);
	feedbackBits = FlipBytesEndian(feedbackBits);

	//To create key bits, making a copy of data input bits
	BitArray ^ keyBits = (BitArray ^)initValueBits->Clone();

	//Going through each data input char to do encryption.
	for(int onChar = 0; onChar < dataBits->Length / 8; onChar++)
	{
		//Running 8-cycle algorithm to get next key bits.
		keyBits = Do8CycleProcedure(keyBits, feedbackBits);

		//Trying to get last byte of key bytes.
		keyBits = FlipBytesEndian(keyBits); //Compiler assumes bytes to be Little Endian
		array<Byte>^ keyBytes = gcnew array<Byte>(keyBits->Length / 8);
		keyBits->CopyTo(keyBytes, 0);

		//Making keyBits Big Endian again.
		keyBits = FlipBytesEndian(keyBits);

		//Sets first byte of encryption result to first data byte xored with data byte
		encryptionResult[onChar] = dataBytes[onChar] ^ keyBytes[keyBytes->Length - 1];
	}

	//Converting encryption result to character array.
	unsigned char * resultInChars = new unsigned char[dataLength];
	for(int onChar = 0; onChar < dataLength; onChar++)
	{
		resultInChars[onChar] = (unsigned char)encryptionResult[onChar];
	}

	//Return final result converted to a char array.
	return resultInChars;
}

///Function to view bits, of bit array, for the purpose of testing.
String ^ ViewBits(BitArray ^ theBits)
{
	//Will hold bit output.
	String ^ bitHolder = "";

	//Goes through all bits to convert them to strings.
	for(int onBit = 0; onBit < theBits->Length; onBit++)
	{
		//Every 4 bit, make space for visual ease.
		if(onBit % 4 == 0)
		{
			bitHolder += " ";
		}

		//Converting bit to string.
		if(theBits[onBit] == false)
		{
			bitHolder += "0";
		}
		else if(theBits[onBit] == true)
		{
			bitHolder += "1";
		}
	}

	//Returning string output of bits.
	return bitHolder;
}
