<?php
ob_start();
session_start();

$myU = $_COOKIE['ce_uid'] ?? '';
$myN = $_COOKIE['ce_nick'] ?? '';

$rDir = 'rooms/';
$up = 'uploads/';
$avatarDir = 'avatars/';
$passF = $rDir . 'users_pass.db.php';
$userDataF = $rDir . 'users_data.db.php';
$listF = $rDir . 'rooms_list.db.php';
$myContactsF = $rDir . "contacts_" . $myU . ".db.php";

if(!is_dir($rDir)) @mkdir($rDir, 0777);
if(!is_dir($up)) @mkdir($up, 0777);
if(!is_dir($avatarDir)) @mkdir($avatarDir, 0777);

if (!file_exists('config.php')) {
    $k = bin2hex(openssl_random_pseudo_bytes(16));
    file_put_contents('config.php', "<?php \$crypto_key = '$k'; ?>");
}
require_once('config.php');

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$is_legacy = preg_match('/(Nokia|Symbian|S60|Opera Mini|MAUI|SC6531E|Spreadtrum|MRE|Dorado)/i', $ua);

function db_append($f, $d) {
    if(!file_exists($f)) file_put_contents($f, "<?php die(); ?>\n");
    return file_put_contents($f, $d . "\n", FILE_APPEND | LOCK_EX);
}

function v_crypt($d, $k, $mode = 'enc') {
    global $is_legacy;
    if ($mode == 'enc') {
        if ($is_legacy) {
            $res = ''; $key = hash('sha256', $k, true);
            for($i=0; $i<strlen($d); $i++) $res .= $d[$i] ^ $key[$i % 32];
            return "X:" . base64_encode($res);
        } else {
            $iv = openssl_random_pseudo_bytes(16);
            $enc = openssl_encrypt($d, "aes-128-ctr", $k, 0, $iv);
            return "A:" . str_replace(['+','/','='], ['-','_',''], base64_encode($iv . "::" . $enc));
        }
    } else {
        $prefix = substr($d, 0, 2); $payload = substr($d, 2);
        if ($prefix === "X:") {
            $res = ''; $key = hash('sha256', $k, true);
            $data = base64_decode($payload);
            if(!$data) return $d;
            for($i=0; $i<strlen($data); $i++) $res .= $data[$i] ^ $key[$i % 32];
            return $res;
        } elseif ($prefix === "A:") {
            $raw = base64_decode(str_replace(['-','_'], ['+','/'], $payload));
            $p = explode("::", $raw);
            if(count($p) < 2) return $d;
            return openssl_decrypt($p[1], "aes-128-ctr", $k, 0, $p[0]);
        }
        return $d;
    }
}

function get_avatar_html($u, $name) {
    global $avatarDir;
    $f = $avatarDir . md5($u) . '.png';
    if(file_exists($f)) return "<img src='$f' width='20' height='20' style='vertical-align:middle; border-radius:50%; margin-right:3px;'>";
    $colors = ['#268bd2', '#b58900', '#cb4b16', '#dc322f', '#2aa198'];
    $c = $colors[abs(crc32($u)) % count($colors)];
    $l = mb_strtoupper(mb_substr($name, 0, 1));
    return "<div style='display:inline-block; width:20px; height:20px; border-radius:50%; background:$c; color:white; text-align:center; line-height:20px; font-size:9px; vertical-align:middle; margin-right:3px;'>$l</div>";
}

function get_user_bio($u) {
    global $userDataF; if(!file_exists($userDataF)) return "";
    $lines = file($userDataF);
    foreach($lines as $l){
        $p = explode('|', trim($l));
        if(count($p) >= 2 && $p[0] == $u) return htmlspecialchars($p[1]);
    } return "";
}


if(isset($_GET['go_pm']) && $myU){
    $u2 = preg_replace('/[^a-z0-9]/', '', $_GET['go_pm']);
    $ids = [$myU, $u2]; sort($ids);
    header("Location: ?to=pm_".$ids[0]."_".$ids[1]); exit;
}

if(isset($_GET['add_con']) && $myU){
    $cid = preg_replace('/[^a-z0-9]/', '', $_GET['add_con']);
    $cnick = htmlspecialchars($_GET['nick'] ?? 'User');
    $found = false;
    if(file_exists($myContactsF)) {
        foreach(file($myContactsF) as $l) { if(strpos($l, "$cid|") === 0) { $found=true; break; } }
    }
    if(!$found && $cid != $myU) db_append($myContactsF, "$cid|$cnick");
    header("Location: ?to=" . ($_GET['to'] ?? 'all')); exit;
}

if(isset($_GET['del_con']) && $myU){
    $cid = $_GET['del_con'];
    if(file_exists($myContactsF)){
        $ls = file($myContactsF); $nl = [];
        foreach($ls as $l){ if(strpos($l, "$cid|") !== 0) $nl[] = $l; }
        file_put_contents($myContactsF, implode('', $nl));
    }
    header("Location: ?view=contacts"); exit;
}

if(isset($_POST['up_prof']) && $myU){
    $bio = str_replace('|', ' ', trim($_POST['bio']));
    $lines = file_exists($userDataF) ? file($userDataF) : ["<?php die(); ?>\n"];
    $new_lines = []; $found = false;
    foreach($lines as $line) {
        if(strpos($line, "$myU|") === 0) { $new_lines[] = "$myU|$bio\n"; $found = true; }
        else { $new_lines[] = $line; }
    }
    if(!$found) $new_lines[] = "$myU|$bio\n";
    file_put_contents($userDataF, implode('', $new_lines));
    if(!empty($_FILES['ava']['name'])){ move_uploaded_file($_FILES['ava']['tmp_name'], $avatarDir . md5($myU) . '.png'); }
    header("Location: ?view=prof"); exit;
}

if(isset($_POST['login'])){
    $u = strtolower(preg_replace('/[^a-z0-9]/','',$_POST['u_id']));
    $p = $_POST['pwd'] ?? ''; $n = htmlspecialchars($_POST['dn'] ?? $u);
    if($u && $p){
        $auth_ok = false;
        if(file_exists($passF)){
            foreach(file($passF) as $line){
                $data = explode('|', trim($line));
                if(count($data) >= 2 && $data[0] == $u){ if(password_verify($p, $data[1])) $auth_ok = true; break; }
            }
        }
        if($auth_ok || !isset($data[0])){
            if(!$auth_ok) db_append($passF, "$u|".password_hash($p, PASSWORD_DEFAULT));
            setcookie('ce_uid', $u, time()+86400*30, "/");
            setcookie('ce_nick', $n, time()+86400*30, "/");
            header("Location: index.php"); exit;
        }
    }
}
if(isset($_GET['logout'])){ setcookie('ce_uid', '', 1, "/"); session_destroy(); header("Location: index.php"); exit; }

$to = preg_replace('/[^a-z0-9_]/', '', $_GET['to'] ?? 'all');
$view = $_GET['view'] ?? 'chat';
$can_read = true;
if(strpos($to, 'pm_') === 0){
    $p = explode('_', $to); if(count($p) < 3 || ($myU != $p[1] && $myU != $p[2])) $can_read = false;
}
if(strpos($to, 'saved_') === 0 && $to != 'saved_'.$myU) $can_read = false;

$curF = ($to == 'all') ? $rDir . "global_chat.db.php" : $rDir . "room_$to.db.php";

if($myU && $can_read && isset($_POST['send_msg'])){
    $m = htmlspecialchars(trim($_POST['msg']));
    $fT = ""; 
    if(!empty($_FILES['f']['name'])){
        $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
        if(in_array($ext, ['jpg','jpeg','png','gif','txt','zip'])){
            $nf = bin2hex(openssl_random_pseudo_bytes(4)).'.'.$ext;
            if(move_uploaded_file($_FILES['f']['tmp_name'], $up.$nf))
                $fT = in_array($ext, ['jpg','png','gif','jpeg']) ? "[img]".$up.$nf."[/img]" : "[file]".$up.$nf."[/file]";
        }
    }
    if($m || $fT){ 
        $final_msg = $m . ($m && $fT ? "\n" : "") . $fT;
        $dat = v_crypt($final_msg, $crypto_key, 'enc'); 
        db_append($curF, "$myN|$dat|".date('H:i')."|$myU"); 
    }
    header("Location: ?to=$to"); exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CrossEra Chat</title>
    <style>
        body { margin:0; font-family:sans-serif; font-size:11px; background:#002b36; color:#839496; }
        .box { max-width:400px; margin:auto; background:#eee8d5; min-height:100vh; color:#073642; border:1px solid #000; }
        .hdr { background:#a01ae8; color:white; padding:5px; font-weight:bold; display:flex; align-items:center; justify-content:space-between; }
        .nav { background:#93a1a1; padding:2px; text-align:center; }
        .nav a { color:#000; text-decoration:none; margin:0 1px; font-size:9px; border:1px solid #777; padding:1px 2px; background:#eee; display:inline-block; }
        #chat { height:350px; overflow-y:scroll; background:white; margin:3px; padding:3px; border:1px solid #999; }
        .m { border-bottom:1px solid #eee; padding:4px; word-wrap:break-word; }
        .btn { background:#46e7f2; color:white; border:1px solid #000; padding:4px; font-size:10px; cursor:pointer; }
        .act-btn { color:#46e7f2; font-weight:bold; text-decoration:none; margin-left:4px; font-size:10px; }
        .logo-login { width: 120px; margin-bottom: 15px; }
    </style>
</head>
<body>
<div class="box">
    <?php if(!$myU): ?>
        <div style="padding:30px 15px; text-align:center;">
            <img src="logo.png" class="logo-login" alt="CrossEra"><br>
            <form method="POST">
                ID: <input name="u_id" size="10" placeholder="логин"><br>
                Ник: <input name="dn" size="10" placeholder="имя"><br>
                Пасс: <input name="pwd" type="password" size="10"><br><br>
                <input type="submit" name="login" value="ВХОД / РЕГ" class="btn">
            </form>
        </div>
    <?php else: ?>
        <div class="hdr">
            <div style="display:flex; align-items:center;">
                <img src="logo.png" height="80" style="margin-right:8px;">
                <?php echo get_avatar_html($myU, $myN); ?> <span><?php echo $myN; ?></span>
            </div>
            <a href="?logout=1" style="color:white; font-size:9px; text-decoration:none;">[Выход]</a>
        </div>
        
        <div class="nav">
            <a href="?to=all">🏠 Глоб.</a>
            <a href="?view=contacts">📖 Конт.</a>
            <a href="?to=saved_<?php echo $myU; ?>">⭐ Избр.</a>
            <a href="?view=rooms">👥 Групп.</a>
            <a href="?view=prof">👤 Проф.</a>
              <a href="?view=about">ℹ️ Инфо</a>
        </div>

        <?php if($view == 'contacts'): ?>
            <div style="padding:15px 10px;">
                <b>Мои контакты:</b><hr>
                <?php if(file_exists($myContactsF)): ?>
                    <?php foreach(file($myContactsF) as $l): if(strpos($l,'<?php')!==false)continue; $p=explode('|',trim($l)); if(count($p)<2)continue; ?>
                        <div class="m">
                            <?php echo get_avatar_html($p[0],$p[1]); ?> <b><?php echo $p[1]; ?></b>
                            <a href="?go_pm=<?php echo $p[0]; ?>" class="act-btn">[ЛС]</a>
                            <a href="?del_con=<?php echo $p[0]; ?>" class="act-btn" style="color:red;">[-]</a>
                        </div>
                    <?php endforeach; ?>
                <?php else: echo "Список пуст."; endif; ?>
            </div>
        <?php elseif($view == 'about'): ?>
    <div style="padding:15px; text-align:center;">
        <img src="logo.png" height="70" style="filter: drop-shadow(0 0 3px white); margin-bottom:10px;">
        <h3 style="margin:5px 0;">CrossEra Chat</h3>
        <small>Версия 1.0 (Stable)</small>
        <hr style="border:0; border-top:1px solid #ccc; margin:15px 0;">
        
        <div style="text-align:left; font-size:12px; line-height:1.5;">
            <p><b>CrossEra</b> — это кросс-платформенный мессенджер, созданный для объединения эпох.</p>
            <ul>
                <li>Работает на PHP 7+</li>
                <li>Шифрование: AES-128 </li>
                <li>Поддержка старых J2ME браузеров</li>
                <li>контакты</li>
            </ul>
            <p style="text-align:center; color:#666; margin-top:20px;">
                Разработано с душой для настоящих гиков.<br>
                &copy; 2026 Impisre software
            </p>
        </div>
        
        <a href="?to=all" class="btn" style="text-decoration:none; display:inline-block; margin-top:10px;">Назад в чат</a>
    </div>
        <?php elseif($view == 'prof'): ?>
            <div style="padding:10px;">
                <b>Профиль:</b><hr>
                ID: <?php echo $myU; ?><br><br>
                <form method="POST" enctype="multipart/form-data">
                    Био: <input name="bio" value="<?php echo get_user_bio($myU); ?>" style="width:80%;"><br><br>
                    Ава (PNG): <br><input type="file" name="ava" size="8"><br><br>
                    <input type="submit" name="up_prof" value="СОХРАНИТЬ" class="btn">
                </form>
            </div>
        <?php elseif($view == 'rooms'): ?>
            <div style="padding:10px;"><b>Группы:</b><br>
            <?php if(file_exists($listF)) foreach(file($listF) as $rl){ $p=explode('|', trim($rl)); if(count($p)<2)continue; echo "• <a href='?to=$p[1]'>$p[0]</a><br>"; } ?>
            </div>
        <?php else: ?>
            <div id="chat">
                <?php if(!$can_read): echo "Ошибка доступа"; else: ?>
                    <small>Комната: <b><?php echo $to; ?></b></small><hr>
                    <?php if(file_exists($curF)) {
                        $lines = file($curF);
                        foreach($lines as $l): 
                            if(strpos($l,'<?php')!==false || !trim($l))continue; 
                            $d=explode('|',trim($l)); if(count($d)<4)continue;
                            $msg = v_crypt($d[1], $crypto_key, 'dec');
                            $msg = preg_replace('/\[img\](.*?)\[\/img\]/i', '<br><img src="$1" style="max-width:150px; border:1px solid #ccc; margin:5px 0;"><br>', $msg);
                            $msg = preg_replace('/\[file\](.*?)\[\/file\]/i', '<br><a href="$1" target="_blank">[Файл: $1]</a>', $msg);
                    ?>
                        <div class="m">
                            <?php echo get_avatar_html($d[3],$d[0]); ?> <b><?php echo $d[0]; ?></b> <small style="color:#999;"><?php echo $d[2]; ?></small>
                            <?php if($d[3]!=$myU): ?>
                                <a href="?add_con=<?php echo $d[3]; ?>&nick=<?php echo $d[0]; ?>&to=<?php echo $to; ?>" class="act-btn">[+]</a>
                                <a href="?go_pm=<?php echo $d[3]; ?>" class="act-btn">[ЛС]</a>
                            <?php endif; ?>
                            <br><div style="margin-top:3px; line-height:1.4;"><?php echo nl2br($msg); ?></div>
                        </div>
                    <?php endforeach; } else { echo "Сообщений пока нет..."; } ?>
                <?php endif; ?>
            </div>
            <form method="POST" enctype="multipart/form-data" style="padding:5px; background:#ddd;">
                <textarea name="msg" style="width:96%; height:40px; font-size:12px;" placeholder="Сообщение..."></textarea><br>
                <div style="margin-top:3px;">
                    <input type="file" name="f" style="font-size:9px; width:150px;">
                    <input type="submit" name="send_msg" value="ОТПРАВИТЬ" class="btn" style="float:right;">
                </div>
            </form>
        <?php endif; ?>
    <?php endif; ?>
</div>
<script>
    var objDiv = document.getElementById("chat");
    if(objDiv) objDiv.scrollTop = objDiv.scrollHeight;
</script>
</body>
</html>
