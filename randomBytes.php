<?php

/*

Secure PHP random bytes
by @shoghicp

Basic Usage: string randomBytes( [ int $length = 16 [, bool $secure = true [, bool $raw = true [, mixed $startEntropy = "" [, &$rounds [, &$drop ]]]]]])

	$length = 16;
	$bytes = randomBytes($length, true, false); //This will return 32 secure hexadecimal characters
	$bytes = randomBytes($length, false, true); //This will return 16 binary characters


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

	function randomBytes($length = 16, $secure = true, $raw = true, $startEntropy = "", &$rounds = 0, &$drop = 0){
		$output = b"";
		$length = abs((int) $length);
		$secureValue = "";
		$rounds = 0;
		$drop = 0;
		while(!isset($output{$length - 1})){
			//some entropy, but works ^^
			$weakEntropy = array(
				is_array($startEntropy) ? implode($startEntropy):$startEntropy,
				serialize(stat(__FILE__)),
				__DIR__,
				PHP_OS,
				microtime(),
				(string) lcg_value(),
				serialize($_SERVER),
				serialize(get_defined_constants()),
				get_current_user(),
				serialize(ini_get_all()),
				(string) memory_get_usage(),
				php_uname(),
				phpversion(),
				extension_loaded("gmp") ? gmp_strval(gmp_random(4)):microtime(),
				zend_version(),
				(string) getmypid(),
				(string) mt_rand(),
				(string) rand(),
				function_exists("zend_thread_id") ? ((string) zend_thread_id()):microtime(),
				var_export(@get_browser(), true),
				function_exists("sys_getloadavg") ? implode(";", sys_getloadavg()):microtime(),
				serialize(get_loaded_extensions()),
				sys_get_temp_dir(),
				(string) disk_free_space("."),
				(string) disk_total_space("."),
				uniqid(microtime(),true),
			);
			
			shuffle($weakEntropy);
			$value = hash("sha256", implode($weakEntropy), true);
			foreach($weakEntropy as $k => $c){ //mixing entropy values with XOR and hash randomness extractor
				$c = (string) $c;
				str_shuffle($c); //randomize characters
				$value ^= hash("md5", $c . microtime() . $k, true) . hash("md5", microtime() . $k . $c, true);
				$value ^= hash("sha256", $c . microtime() . $k, true);
			}
			unset($weakEntropy);
			
			if($secure === true){
				$strongEntropy = array(
					is_array($startEntropy) ? $startEntropy[($rounds + $drop) % count($startEntropy)]:$startEntropy, //Get a random index of the startEntropy, or just read it
					file_exists("/dev/urandom") ? fread(fopen("/dev/urandom", "rb"), 512):"",
					(function_exists("openssl_random_pseudo_bytes") and version_compare(PHP_VERSION, "5.3.4", ">=")) ? openssl_random_pseudo_bytes(512):"",
					function_exists("mcrypt_create_iv") ? mcrypt_create_iv(512, MCRYPT_DEV_URANDOM) : "",
					$value,
				);
				shuffle($strongEntropy);
				$strongEntropy = implode($strongEntropy);
				$value = "";
				//Von Neumann randomness extractor, increases entropy
				$len = strlen($strongEntropy) * 8;
				for($i = 0; $i < $len; $i += 2){
					$a = ord($strongEntropy{$i >> 3});
					$b = 1 << ($i % 8);
					$c = 1 << (($i % 8) + 1);
					$b = ($a & $b) === $b ? "1":"0";
					$c = ($a & $c) === $c ? "1":"0";
					if($b !== $c){
						$secureValue .= $b;
						if(isset($secureValue{7})){
							$value .= chr(bindec($secureValue));
							$secureValue = "";
						}
						++$drop;
					}else{
						$drop += 2;
					}
				}
			}
			$output .= substr($value, 0, min($length - strlen($output), $length));
			unset($value);
			++$rounds;
		}
		return $raw === false ? bin2hex($output):$output;
	}