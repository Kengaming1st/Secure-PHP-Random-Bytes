<?php
/*

Secure PHP random bytes
by @shoghicp

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

include("randomBytes.php");


echo "Stream: ".randomBytes(32, true, false, "", $rounds, $drop).PHP_EOL; //This will return an output of 32 bytes hex-encoded, and using secure reconbination of data.
echo "Rounds: ".$rounds.PHP_EOL;
$tBits = $rounds * 16 * 8; //Total number of bits generated
echo "Total bits: ".$tBits.PHP_EOL;
echo "Dropped bits: ".$drop." ".round(($drop / $tBits) * 100, 2)."%".PHP_EOL;