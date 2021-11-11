#pragma once

#include "fmt/core.h"
#include "fmt/color.h"

#include "macros.hpp"
#include "singleton.hpp"

#include <Windows.h>

#include <string>
#include <string_view>
#include <optional>

#pragma warning ( disable : 4091 )

typedef enum printa_e : uint32_t
{
	ok         = 0,
	input      = 1,
	load	   = 2,
	fail       = 3,
	info	   = 4,
};

class printa_c : public singleton<printa_c>
{
public:

	inline printa_c( )
	{
		const auto console_handle = GetConsoleWindow( );
		const auto stream_handle = GetStdHandle( STD_OUTPUT_HANDLE );

		// colours
		SetConsoleMode( stream_handle, 0x7 );

		// transparency
		SetLayeredWindowAttributes( console_handle, 0, 242, LWA_ALPHA );

		// name
		SetConsoleTitleA( "" );

		CloseHandle( console_handle );
	}
	inline ~printa_c( ) = default;

	// --

	template <printa_e type = printa_e::ok, typename ...args_t> 
	constexpr __forceinline auto print( const std::string_view format, args_t... args ) -> void
	{
		PRINTA_PRE( );

		const auto [fmt_style, fmt_str] = this->get_format<type>( );
		fmt::print( fmt_style, fmt_str );

		PRINTA_POST( );

		fmt::print( format.data( ), args... );
	}

	template <printa_e type = printa_e::ok, typename ...args_t>
	constexpr __forceinline auto print( const std::wstring_view format, args_t... args ) -> void
	{
		PRINTA_PRE( );

		const auto [fmt_style, fmt_str] = this->get_format<type>( );
		fmt::print( fmt_style, fmt_str );

		PRINTA_POST( );

		fmt::print( format.data( ), args... );
	}

	// --

	template <uint32_t indentation = 5>
	constexpr __forceinline auto project( const std::string_view project_name = "pe-parser by zhitkur" ) -> void
	{
		std::string pre{ "\n" }; for ( auto idx = 0u; idx < indentation; idx++ ) { pre += std::string{ " " }; }

		fmt::print( pre );
		fmt::print( fg( fmt::color::dark_turquoise) | fmt::emphasis::underline | fmt::emphasis::bold, project_name.data( ) );
		fmt::print( "\n\n" );
	}

	template <uint32_t indentation = 8>
	constexpr __forceinline auto project_dos(const std::string_view project_name = "DOS Header") -> void
	{
		std::string pre{ "\n" }; for (auto idx = 0u; idx < indentation; idx++) { pre += std::string{ " " }; }

		fmt::print(pre);
		fmt::print(fg(fmt::color::salmon) | fmt::emphasis::underline | fmt::emphasis::bold, project_name.data());
		fmt::print("\n\n");
	}

	template <uint32_t indentation = 8>
	constexpr __forceinline auto project_nt(const std::string_view project_name = "NT Header") -> void
	{
		std::string pre{ "\n" }; for (auto idx = 0u; idx < indentation; idx++) { pre += std::string{ " " }; }

		fmt::print(pre);
		fmt::print(fg(fmt::color::salmon) | fmt::emphasis::underline | fmt::emphasis::bold, project_name.data());
		fmt::print("\n\n");
	}

	template <uint32_t indentation = 2>
	constexpr __forceinline auto project_file(const std::string_view project_name = "NT Header -> File Header") -> void
	{
		std::string pre{ "\n" }; for (auto idx = 0u; idx < indentation; idx++) { pre += std::string{ " " }; }

		fmt::print(pre);
		fmt::print(fg(fmt::color::salmon) | fmt::emphasis::underline | fmt::emphasis::bold, project_name.data());
		fmt::print("\n\n");
	}

	template <uint32_t indentation = 1>
	constexpr __forceinline auto project_option(const std::string_view project_name = "NT Header -> Optional Header") -> void
	{
		std::string pre{ "\n" }; for (auto idx = 0u; idx < indentation; idx++) { pre += std::string{ " " }; }

		fmt::print(pre);
		fmt::print(fg(fmt::color::salmon) | fmt::emphasis::underline | fmt::emphasis::bold, project_name.data());
		fmt::print("\n\n");
	}

private:

	template <printa_e type>
	constexpr __forceinline auto get_format( ) -> std::pair<fmt::v7::text_style, std::string_view>
	{
		std::pair<fmt::v7::text_style, std::string_view> values = {};

		switch ( type )
		{
		case ok:       
		{
			values.first = fg( fmt::color::lime_green );
			values.second = " Ok ";
			break;
		}
		case input:
		{
			values.first = fg( fmt::color::dodger_blue );
			values.second = " -> ";
			break;
		}
		case load:
		{
			values.first = fg( fmt::color::lemon_chiffon);
			values.second = "Wait";
			break;
		}
		case fail:
		{
			values.first = fg( fmt::color::orange_red );
			values.second = "Fail";
			break;
		}
		case info:
			values.first = fg(fmt::color::dark_khaki);
			values.second = "Info";
			break;
		}

		return values;
	}
};

inline auto printa = printa_c::instance( );