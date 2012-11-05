<?php

/*

Secure PHP random bytes
by @shoghicp

Basic Usage: string randomBytes( [ int $lenght = 16 [, bool $secure = true [, bool $raw = true [, mixed $startEntropy = "" [, &$rounds [, &$drop ]]]]]])

	$lenght = 16;
	$bytes = randomBytes($lenght, true, false); //This will return 32 secure hexadecimal characters
	$bytes = randomBytes($lenght, false, true); //This will return 16 binary characters


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

	function randomBytes($lenght = 16, $secure = true, $raw = true, $startEntropy = "", &$rounds = 0, &$drop = 0){
		$output = b"";
		$lenght = abs((int) $lenght);
		$rounds = 0;
		$drop = 0;
		while(!isset($output{$lenght - 1})){
			//some entropy, but works ^^
			$entropy = array(
				is_array($startEntropy) ? $startEntropy[($rounds + $drop) % count($startEntropy)]:$startEntropy, //Get a random index of the startEntropy, or just read it
				serialize(stat(__FILE__)),
				__DIR__,
				PHP_OS,
				microtime(),
				lcg_value(),
				serialize($_SERVER),
				serialize(get_defined_constants()),
				get_current_user(),
				serialize(ini_get_all()),
				(string) memory_get_usage(),
				php_uname(),
				phpversion(),
				extension_loaded("gmp") ? gmp_strval(gmp_random(4)):microtime(),
				zend_version(),
				getmypid(),
				(string) mt_rand(),
				(string) rand(),
				serialize(get_loaded_extensions()),
				sys_get_temp_dir(),
				disk_free_space("."),
				disk_total_space("."),
				(function_exists("openssl_random_pseudo_bytes") and version_compare(PHP_VERSION, "5.3.4", ">=")) ? openssl_random_pseudo_bytes(16):microtime(true),
				function_exists("mcrypt_create_iv") ? mcrypt_create_iv(16, MCRYPT_DEV_URANDOM) : microtime(true),
				uniqid(microtime(true),true),
				file_exists("/dev/urandom") ? fread(fopen("/dev/urandom", "rb"),256):microtime(true),
			);
			
			shuffle($entropy);
			$value = str_repeat("\x00", 16);
			foreach($entropy as $k => $c){ //mixing entropy values with XOR and hash randomness extractor
				$c = (string) $c;
				str_shuffle($c); //randomize characters
				for($i = 0; $i < 32; $i += 16){
					$value ^= hash("md5", $i . $c . microtime() . $k, true);
					$value ^= substr(hash("sha256", $i . $c . microtime() . $k, true), $i, 16);
					$value ^= hash("ripemd128", $i . $c . microtime() . $k, true);
				}
				
			}
			unset($entropy);
			
			if($secure === true){
				//Von Neumann randomness extractor, increases entropy
				$secureValue = "";
				for($i = 0; $i < 128; $i += 2){
					$a = ord($value{$i >> 3});
					$b = 1 << ($i % 8);
					$c = 1 << (($i % 8) + 1);
					$b = ($a & $b) === $b ? "1":"0";
					$c = ($a & $c) === $c ? "1":"0";
					if($b !== $c){
						$secureValue .= $b;
						++$drop;
					}else{
						$drop += 2;
					}
				}
				$value = "";
				$secureValue = str_split($secureValue, 8);
				foreach($secureValue as $c){
					$value .= chr(bindec($c));
				}
			}
			$output .= substr($value, 0, min($lenght - strlen($output), $lenght));
			unset($value, $secureValue);
			++$rounds;
		}
		return $raw === false ? bin2hex($output):$output;
	}