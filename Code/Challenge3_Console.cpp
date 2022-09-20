//Timothy Edwards - "Challenge 3: Obfuscated JPEGs"

// Challenge3_Console.cpp : main project file.

#include "stdafx.h"
#include "DataProcessing.h"

using namespace System;

///Initial value for crypt function.
static int initValue = 0x4F574154;

///Reads and crypts magic file
String ^ ReadMagic(String ^filePath)
{
	//Sets up file reader with file specified.
	FileStream ^ fs = gcnew FileStream(filePath, FileMode::Open);

	//Reading HEAD.
	System::Byte MAGIC[6];
	System::Int32 ENTRY_ptr = 0;

	//Reading MAGIC
	for(int onByte = 0; onByte < 6; onByte++)
	{
		MAGIC[onByte] = fs->ReadByte();
	}

	//Reading ENTRY pointer.
	for(int onByte = 0; onByte < 4; onByte++)
	{
		ENTRY_ptr += (int)fs->ReadByte() * Math::Pow(256, onByte);
	}

	//Seek to start of ENTRY_LIST.
	fs->Seek(ENTRY_ptr, SeekOrigin::Begin);

	//Going through ENTRYs in ENTRY_LIST.
	for(int onEntry = 0; onEntry < 127; onEntry++)
	{
		/*Used to check if first four bytes (of ENTRY) are each 0xFF.  If they are, program has
		already read past all of the ENTRYs in ENTRY_LIST*/
		int firstFourBytesAdded = 0;

		//Go through start of ENTRY NAME to see if end of ENTRY characters are found.
		for(int onChar = 0; onChar < 4; onChar++)
		{
			//Adds ENTRY NAME character to incrementer used to detect end of ENTRY list.
			firstFourBytesAdded += (int)fs->ReadByte();
		}

		/*If first four bytes added together are 1020, each byte is 0xFF.  Four of such bytes means
		end of ENTRY list.*/
		if(firstFourBytesAdded == 1020)
		{
			//Breaking out of loop that iterates through ENTRYs.
			break;
		}

		//Skipping past rest of ENTRY NAME characters.
		fs->Position += 12;

		//Go through BLOCK_LIST in ENTRY.
		int BLOCK_LIST_ptr = 0;
		for(int onByte = 0; onByte < 4; onByte++)
		{
			BLOCK_LIST_ptr += (int)fs->ReadByte() * Math::Pow(256, onByte);
		}

		//Seeking to start of BLOCK_LIST.
		fs->Seek(BLOCK_LIST_ptr, SeekOrigin::Begin);

		//Going through BLOCKs in BLOCK_LIST.
		for(int onBlock = 0; onBlock < 255; onBlock++)
		{
			//Going through BLOCK SIZE characters.
			int SIZE = (int)fs->ReadByte() + (int)fs->ReadByte() * 256;

			//Going through BLOCK DATA characters.  First, getting data pointer
			array<Byte> ^ Data_ptr_bytes = gcnew array<Byte>(5);
			fs->Read(Data_ptr_bytes, 0, 4);
			int DATA_ptr = (int)Data_ptr_bytes[0] + (int)Data_ptr_bytes[1] * 256 +
						(int)Data_ptr_bytes[2] * Math::Pow(256, 2) + (int)Data_ptr_bytes[3] *
						Math::Pow(256, 3);

			/*If the first four bytes in the BLOCK are 0xFF, then the end of the BLOCK_LIST is
			reached and a BLOCK is not being dealt with.  Otherwise, assuming a BLOCK SIZE is found.*/
			if((SIZE == 0xFFFF) && ((int)Data_ptr_bytes[0] == 0xFF) && ((int)Data_ptr_bytes[1]
			== 0xFF))
			{
				//Set position to next ENTRY.
				ENTRY_ptr += 20;
				fs->Position = ENTRY_ptr;

				//Break out of BLOCK reader loop and go to ENTRY reader loop.
				break;
			}

			//Seeking to data pointer.
			fs->Seek(DATA_ptr, SeekOrigin::Begin);

			//Will hold a DATA chunk.
			unsigned char * DATA = new unsigned char[SIZE];

			//Going through data at data pointer's target.
			for(int onByte = 0; onByte < SIZE; onByte++)
			{
				//Storing and character that is not yet been crypted.
				DATA[onByte] = (Char)fs->ReadByte();
			}

			//Done reading magic file.  Closing file.
			fs->Close();

			//Crypting data before putting it in return string.
			unsigned char * DATA_crypted =  Crypt(DATA, SIZE, initValue);

			//Putting crypted data, character by character, in return string.
			String ^ magicText = "";
			for(int onChar = 0; onChar < SIZE; onChar++)
			{
				magicText += (Char)DATA_crypted[onChar];
			}

			//Return magic text that is found.
			return magicText;
		}
	}

	//If no data is found, return is null.
	return nullptr;
}

/// Carves images and tells information about them.
void CreateFiles(String ^inputFilePath, String ^magicFilePath)
{
		//First, find out what magic bytes to be looking for.
		String ^ magicChars = ReadMagic(magicFilePath);

		//Start process of reading input.bin and writing image files
		FileStream ^ fin = gcnew FileStream(inputFilePath, FileMode::Open);
		FileStream ^ fout;

		//Keeps track of how many image files have been created.
		int onOutFile = 0;

		//Will indicate status of image reader.
		bool inImage = false; //Currently reading an image.
		bool onFirstEndChar = false; //Could be end of image

		//Read through input file.  First, look for "start ASCII" characters.
		while(true)
		{
			//If currently reading an image.
			if(inImage)
			{
				//Read input file byte.  Such a byte may be image content or an end of file indicator.
				int currentByte = fin->ReadByte();

				//Writing to byte to output file.
				fout->WriteByte((Byte)currentByte);

				//If last byte read was first "end of image" character and current byte is 0xD9.
				if(onFirstEndChar && (currentByte == 217))
				{
					/*Take note of file path before file stream gets deleted (file will need to be
					used for MD5).*/
					String ^ filePath = fout->Name;

					//Close output file and indicate not "inImage".
					fout->Close();
					delete fout;
					inImage = false;

					//Indicate moving on to next output file.
					onOutFile++;
						 
					//Displaying information about image.
					array<String^> ^ md5AndSize = doMd5Hash(filePath);
					Console::WriteLine("\r\n---->Size: " + md5AndSize[1] + " bytes");
					Console::WriteLine("\r\n---->MD5 (HEX): " + md5AndSize[0]);
				}

				//If byte is 0xFF, then current image may be over.
				onFirstEndChar = ((int)currentByte == 255);
			}
			else //If not currently reading an image.
			{
					//Used to indicate stream of info in question is not image file start bytes.
					bool notStartBytes = false;

					//While reading input file, look for first character of "start ASCII".
					if((Char)fin->ReadByte() == magicChars->default[0])
					{
						//If first character is found, see if following characters match.
						for(int onChar = 1; onChar < magicChars->Length; onChar++)
						{
							//If a subsequent character does not match "start ASCII"
							if((Char)fin->ReadByte() != magicChars->default[onChar])
							{
								notStartBytes = true;
							}
						}
					}
					else //If first character does not even match "start ASCII".
					{
						notStartBytes = true;
					}

					//If start bytes have been encountered, make a new output file.
					if(!notStartBytes)
					{
						//Get ready to create an output file.
						String ^ outputDir = Path::GetDirectoryName(inputFilePath) + "\\" +
												Path::GetFileNameWithoutExtension(inputFilePath) +
												"_Repaired";
						String ^ filePath = outputDir + "\\" + fin->Position + ".jpg";

						//Create output directory.
						Directory::CreateDirectory(outputDir);

						/*Attempts to create output file.  Permission error may occur if file was recently
						written to.*/
						try
						{
							//Creates output file.  If it exists, ask user if he/she wants to replace it.
							if(File::Exists(filePath))
							{
								/*Asks if user wants to replace file.  If yes, overwrite file.  If not, set
								file stream to null.*/
								Console::WriteLine("");
								Console::WriteLine(filePath + " already exists.  Do you want to overwrite it?" +
													" (Y/N)");
								String ^ replaceAnswer = Console::ReadLine();
								if((replaceAnswer == "Y") || (replaceAnswer == "y"))
								{
									fout = gcnew FileStream(filePath, FileMode::Create);
								}
								else
								{
									fout = nullptr;
								}
							}
							else
							{
								//Create output file.
								fout = gcnew FileStream(filePath, FileMode::CreateNew);
							}
						}
						catch(System::IO::IOException ^ex)
						{
							Console::WriteLine(ex->Message + "\r\n\r\nRestarting the Challenge program might help.");
						}

						//If an output location is set.
						if(fout != nullptr)
						{
							//Write initial bytes for JPEG file.
							fout->WriteByte((Byte)255);
							fout->WriteByte((Byte)216);
							fout->WriteByte((Byte)255);

							//Displaying information about image.
							Console::WriteLine("\r\n->File: " + filePath);
							Console::WriteLine("\r\n---->Offset: " + fin->Position + " bytes");

							//Indicate image is now being read.
							inImage = true;
						}
					}
				}

				//If more bytes to read.
				if(fin->ReadByte() != -1)
				{
					//Just checking if file's end was reached.  Don't want to seek file reader.
					fin->Position--;

					//Continue on trying to read file.
					continue;
				}

				//Statements run if no more bytes to read.
				fin->Close();
				break;
		}
}

/// Program's MAIN function.
int main(array<System::String ^> ^args)
{
    //Introduce Challenge 3 Program.  Ask user to proceed with running challenge.
	Console::WriteLine(L"*****************************************************************************");
	Console::WriteLine(L"Challenge 3: Obfuscated JPEGs");
	Console::WriteLine(L"*****************************************************************************");
	Console::WriteLine(L"Press ENTER to run challenge...");
	if(Console::ReadKey().Key == ConsoleKey::Enter)
	{
		//Deafult path of input.bin is the following.
		String ^ fileInput = "C:\\Users\\Timothy E\\Documents\\Visual Studio for CTS\\SW_2018\\SW_2018\\" +
							  "input.bin";

		//Default path of magic.kdb is the following.
		String ^ magicFile = "C:\\Users\\Timothy E\\Documents\\Visual Studio for CTS\\SW_2018\\SW_2018\\" +
							  "magic.kdb";

		//Asks user if default input file path is right.  If not, asks user to input it.
		Console::WriteLine(L"\r\nIs the following file path, to 'input.bin', right? '" + fileInput +
						"'.\r\nIf so, presss ENTER now.  If not, enter the right path then press ENTER: ");
	
		//Has user entered his/her own path for input file.  If so, change file input as such.
		String ^ fileInputResponse = Console::ReadLine();
		fileInput = (fileInputResponse == "" ? fileInput : fileInputResponse);

		//Asks user if default magic file path is right.  If not, asks user to input it.
		Console::WriteLine(L"\r\nIs the following file path, to 'magic.kdb', right? '" + magicFile +
						"'.\r\nIf so, presss ENTER now.  If not, enter the right path then press ENTER: ");

		//Has user entered his/her own path for magic file.  If so, change magic file input as such.
		String ^ magicFiletResponse = Console::ReadLine();
		magicFile = (magicFiletResponse == "" ? magicFile : magicFiletResponse);

		/*Attempts to run function to carve image files, given main input file and magic file.  An exception
		might occur due to bad file paths inputed.*/
		try
		{
			//Runs function to carve image files, given main input file and magic file.
			CreateFiles(fileInput, magicFile);
		}
		catch(System::Exception ^exception)
		{
			Console::WriteLine(L">>>>>>ERROR: There may be a problem with one of the file paths entered.  " +
								"OFFICIAL ERROR MESSAGE: \"" + exception->Message + "\"<<<<<<");
		}

		//Indicate program is done carving image files.
		Console::WriteLine(L"");
		Console::WriteLine(L"==================================================================================");
		Console::WriteLine(L"");
		Console::WriteLine(L"Image carving process complete.  Press ENTER to exit.");
		if(Console::ReadKey().Key == ConsoleKey::Enter)
		{
			Environment::Exit(0);
		}
	}
    return 0;
}
