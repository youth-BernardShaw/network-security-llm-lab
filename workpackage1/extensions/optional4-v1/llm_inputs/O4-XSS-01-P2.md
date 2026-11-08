样本ID：O4-XSS-01
输入包：O4-XSS-01-P2
输入版本：v2；扩展集：optional4-v1
审计范围：XSS
业务规格：用户注册、登录后显示用户名；所有显示内容按HTML文本处理。
调用范围：注册、登录和登录后的用户名输出页面；在同一会话中关联数据库返回值。
条件与限制：已提供相关注册、登录、显示与数据库连接代码；本地路径和数据库字段长度由验证阶段确认。
来源通过内部同ID台账追溯；当前输入不含历史结论、POC和实测证据。

片段：O4-XSS-01-B；作用：登录处理；局部行号从1起始。
```php
<html>
<head>
</head>
<body bgcolor="#000000">
<font size="3" color="#FFFF00">
<div align="right">
<a style="font-size:.8em;color:#FFFF00" href='index.php'><img src="../images/Home.png" height='45'; width='45'></br>HOME</a>
</div>
<?PHP

session_start();
//including the Mysql connect parameters.
include("../sql-connections/sql-connect.php");




function sqllogin(){

   $username = mysql_real_escape_string($_POST["login_user"]);
   $password = mysql_real_escape_string($_POST["login_password"]);
   $sql = "SELECT * FROM users WHERE username='$username' and password='$password'";
//$sql = "SELECT COUNT(*) FROM users WHERE username='$username' and password='$password'";
   $res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( ');
   $row = mysql_fetch_row($res);
	//print_r($row) ;
   if ($row[1]) {
			return $row[1];
   } else {
      		return 0;
   }

}






$login = sqllogin();
if (!$login== 0) 
{
	$_SESSION["username"] = $login;
	setcookie("Auth", 1, time()+3600);  /* expire in 15 Minutes */
	header('Location: logged-in.php');
} 
else
{
?>
<tr><td colspan="2" style="text-align:center;"><br/><p style="color:#FF0000;">
<center>
<img src="../images/slap1.jpg">
</center>
</p></td></tr>
<?PHP
} 
?>






</body>
</html>
```

片段：O4-XSS-01-C；作用：登录后页面；局部行号从1起始。
```php
<?PHP
session_start();
if (!isset($_COOKIE["Auth"]))
{
	if (!isset($_SESSION["username"])) 
	{
   		header('Location: index.php');
	}
	header('Location: index.php');
}
?>
<html>
<head>
<title>
</title>
</head>
<body bgcolor="#000000">
<div align="right">
<a style="font-size:.8em;color:#FFFF00" href='index.php'><img src="../images/Home.png" height='45'; width='45'></br>HOME</a></br></br></br>
</div>
<center>
<img src="../images/Logged-in.jpg"></br><font size="4" color="#FFFF00"></br></br>
YOU ARE LOGGED IN AS </br> 
<font size="7" color="#FFFF00"><strong>
<?php
echo $_SESSION["username"];
?>
</strong>
</br>
</br>
<font size="5" color="#FFFF00">
You can Change your password here.


<form name="mylogin" method="POST" action="pass_change.php">
<table style="margin-top:50px;">
<tr>
<td style="text-align:right">
<font size="3" color="#FFFF00">
<strong>Current Password:</strong></font>
</td>
	<td style="text-align:left">
		<input name="current_password" id="current_password" type="text" value="" /> 
	</td>
</tr>
<tr>
<td style="text-align:right">
<font size="3" color="#FFFF00">
	<strong>New Password:</strong>
</font>
</td>
<td style="text-align:left">
	<input name="password" id="password" type="password" value="" />
</td>
</tr>

<tr>
<td style="text-align:right">
<font size="3" color="#FFFF00">
<strong>Retype Password:</strong>
</font>
</td>
<td style="text-align:left">
<input name="re_password" id="re_password" type="password" value="" />
</td>
</tr>




<tr>
<td colspan="2" style="text-align:right">
<input name="submit" id="submit" type="submit" value="Reset" />

</td>
</tr>

<tr>
<td colspan="2" style="text-align:right">
<input name="submit1" id="submit1" type="submit" value="Logout" /><br/><br/>
</td>
</tr>

</table>



</center>
</body>
</html>
```

片段：O4-XSS-01-D；作用：数据库连接依赖；局部行号从1起始。
```php
<?php

//including the Mysql connect parameters.
include("../sql-connections/db-creds.inc");
@error_reporting(0);
@$con = mysql_connect($host,$dbuser,$dbpass);
// Check connection
if (!$con)
{
    echo "Failed to connect to MySQL: " . mysql_error();
}


    @mysql_select_db($dbname,$con) or die ( "Unable to connect to the database: $dbname");






$sql_connect = "SQL Connect included";
############################################
# For Less-24
$form_title_in="Please Login to Continue";
$form_title_ns="New User";
$feedback_title_ns="New User";
$form_title_ns= "Less-24";

############################################
# For Challenge series--- Randomizing the Table names.

?>
```

收到同一父样本全部包后综合判断；缺包时只记录局部证据，不虚构外部实现或运行结果。
