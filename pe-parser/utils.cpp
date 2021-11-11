#include "utils.h"
#pragma warning ( disable : 4311 4302 4312 )

void utils::pe_parser()
{
	std::ifstream target(m_file.c_str(), std::ios_base::in | std::ios_base::binary);

	if (target.is_open())
	{
		printa->print<ok>("Found target file -> ({})\n", m_file);

		//! Get file size -> dynamic allocate buffer
		target.seekg(0, std::ios::end);
		size_t length = target.tellg();
		m_buffer = new char[length];
		//! Back to orig
		target.seekg(0, std::ios::beg);

		//! Get size of killobyte
		size_t kb = length / 1024;	

		printa->print<info>("File size -> [ {} KB ({:d} bytes)  ]\n", kb, length);

		target.read(m_buffer, length);
		printa->print<load>("File infomation loading...\n");

		IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)m_buffer;
		IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((ULONG64)m_buffer + pDos->e_lfanew);

		/*
		-------------------------  DOS Header ----------------------------------------
		*/

		printa->project_dos();

		printa->print<info>("e_magic -> 0x{:X}\n", pDos->e_magic);
		printa->print<info>("e_lfanew -> 0x{:X}\n", pDos->e_lfanew);

		/*
		-------------------------  NT Header ----------------------------------------
		*/

		printa->project_nt();

		printa->print<info>("Signature -> 0x{:X}\n", pNt->Signature);
		
		/*
		-------------------------  File Header ----------------------------------------
		*/

		printa->project_file();

		auto machine = pNt->FileHeader.Machine;
		std::string machine_str;

		switch (machine)
		{
		case IMAGE_FILE_MACHINE_I386:
			machine_str = "Intel 386 (0x14C)";
			break;
		case IMAGE_FILE_MACHINE_IA64:
			machine_str = "Intel 64 (0x200)";
			break;
		default:
			machine_str = "Unknown";
			break;
		}

		time_t time = pNt->FileHeader.TimeDateStamp;

		printa->print<info>("Machine -> {}\n", machine_str);
		printa->print<info>("NumberOfSections -> {}\n", pNt->FileHeader.NumberOfSections);
		printa->print<info>("TimeDateStamp -> [0x{:X}] {}", pNt->FileHeader.TimeDateStamp, ctime(&time));
		printa->print<info>("SizeOfOptionalHeader -> 0x{:X}\n", pNt->FileHeader.SizeOfOptionalHeader);
		printa->print<info>("Characteristics -> 0x{:X}\n", pNt->FileHeader.Characteristics);

		/*
		-------------------------  Option Header ----------------------------------------
		*/

		printa->project_option();
		
		auto magic = pNt->OptionalHeader.Magic;
		std::string magic_str;

		switch (magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			magic_str = "PE32 (0x10B)";
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			magic_str = "PE32+ (0x20B)";
			break;
		case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
			magic_str = "ROM image (0x107)";
			break;
		default:
			magic_str = "Unknown";
			break;
		}

		auto subsystem = pNt->OptionalHeader.Subsystem;
		std::string sub_str;

		switch (subsystem)
		{
		case IMAGE_SUBSYSTEM_NATIVE:
			sub_str = "Driver (0x0)";
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			sub_str = "GUI (0x1)";
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			sub_str = "CUI (0x2)";
			break;
		default:
			sub_str = "Unknown";
			break;
		}

		printa->print<info>("Magic -> {}\n", magic_str);
		printa->print<info>("AddressOfEntryPoint -> 0x{:X}\n", pNt->OptionalHeader.AddressOfEntryPoint);
		printa->print<info>("ImageBase -> 0x{:X}\n", pNt->OptionalHeader.ImageBase);
		printa->print<info>("SectionAlignment -> 0x{:X}\n", pNt->OptionalHeader.SectionAlignment);
		printa->print<info>("FileAlignment -> 0x{:X}\n", pNt->OptionalHeader.FileAlignment);
		printa->print<info>("SizeOfimage -> 0x{:X}\n", pNt->OptionalHeader.SizeOfImage);
		printa->print<info>("SizeOfHeaders -> 0x{:X}\n", pNt->OptionalHeader.SizeOfHeaders);
		printa->print<info>("Subsystem -> {}\n", sub_str);
		printa->print<info>("NumberOfRvaAndSizes -> 0x{:X}\n\n", pNt->OptionalHeader.NumberOfRvaAndSizes);
	}

	printa->print<ok>("Done!\n");
}