<?php
define('DB_USER', "root"); // db user
define('DB_PASSWORD', ""); // db password
define('DB_DATABASE', "vtsdb"); // database name
define('DB_SERVER', "localhost"); // db server
$con = mysqli_connect(DB_SERVER,DB_USER,DB_PASSWORD,DB_DATABASE);
// Checking the connection
if(mysqli_connect_errno())
{
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
}else
{
	echo "Connection Successfull ";
}
?>