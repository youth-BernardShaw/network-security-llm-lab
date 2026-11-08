样本ID：O4-XSS-01
输入包：O4-XSS-01-P1
输入版本：v2；扩展集：optional4-v1
审计范围：XSS
业务规格：用户注册、登录后显示用户名；所有显示内容按HTML文本处理。
调用范围：注册、登录和登录后的用户名输出页面；在同一会话中关联数据库返回值。
条件与限制：已提供相关注册、登录、显示与数据库连接代码；本地路径和数据库字段长度由验证阶段确认。
来源通过内部同ID台账追溯；当前输入不含历史结论、POC和实测证据。

片段：O4-XSS-01-A；作用：注册处理；局部行号从1起始。
```php
<html>
<head>
</head>
<body bgcolor="#000000">
<?PHP
session_start();
?>
<div align="right">
<a style="font-size:.8em;color:#FFFF00" href='index.php'><img src="../images/Home.png" height='45'; width='45'></br>HOME</a>
</div>
<?php

//including the Mysql connect parameters.
include("../sql-connections/sql-connect.php");



if (isset($_POST['submit']))
{
	

# Validating the user input........

	//$username=  $_POST['username'] ;
	$username=  mysql_escape_string($_POST['username']) ;
	$pass= mysql_escape_string($_POST['password']);
	$re_pass= mysql_escape_string($_POST['re_password']);
	
	echo "<font size='3' color='#FFFF00'>";
	$sql = "select count(*) from users where username='$username'";
	$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');
  	$row = mysql_fetch_row($res);
	
	//print_r($row);
	if (!$row[0]== 0) 
		{
		?>
		<script>alert("The username Already exists, Please choose a different username ")</script>;
		<?php
		header('refresh:1, url=new_user.php');
   		} 
		else 
		{
       		if ($pass==$re_pass)
			{
				# Building up the query........
   				
   				$sql = "insert into users ( username, password) values(\"$username\", \"$pass\")";
   				mysql_query($sql) or die('Error Creating your user account,  : '.mysql_error());
					echo "</br>";
					echo "<center><img src=../images/Less-24-user-created.jpg><font size='3' color='#FFFF00'>";   				
					//echo "<h1>User Created Successfully</h1>";
					echo "</br>";
					echo "</br>";
					echo "</br>";					
					echo "</br>Redirecting you to login page in 5 sec................";
					echo "<font size='2'>";
					echo "</br>If it does not redirect, click the home button on top right</center>";
					header('refresh:5, url=index.php');
			}
			else
			{
			?>
			<script>alert('Please make sure that password field and retype password match correctly')</script>
			<?php
			header('refresh:1, url=new_user.php');
			}
		}
}



?>

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
