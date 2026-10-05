<?php
ob_start();
session_start();

$adminID = 'admin';
$rDir = 'rooms/';
$up = 'uploads/';
$avatarDir = 'avatars/';
$modDir = 'mods/';
$reacDir = 'reacs/';
$viewsDir = 'views_counter/';

foreach([$rDir, $up, $avatarDir, $modDir, $reacDir, $viewsDir] as $dir) {
    if(!is_dir($dir)) @mkdir($dir, 0777);
}

if (!file_exists('config.php')) {
    $k = bin2hex(openssl_random_pseudo_bytes(16));
    file_put_contents('config.php', "<?php \$crypto_key = '$k'; ?>");
}
require_once('config.php');

$passF    = $rDir . 'users_pass.db.php';
$groupsF  = $rDir . 'groups_list.db.php';
$onlineF  = $rDir . 'online.db.php';
$unreadF  = $rDir . 'unread_tracker.db.php';
$reqF     = $rDir . 'contact_requests.db.php';
$loginsF  = $rDir . 'login_log.db.php';

$myU = $_SESSION['ce_uid'] ?? '';
$myN = $_SESSION['ce_nick'] ?? '';

/* ---------- CSRF ---------- */
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(openssl_random_pseudo_bytes(16));
}
$csrf = $_SESSION['csrf'];

function csrf_ok() {
    $t = $_REQUEST['csrf'] ?? '';
    return is_string($t) && $t !== '' && hash_equals($_SESSION['csrf'] ?? '', $t);
}

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/* ---------- Тема ---------- */
$theme = $_COOKIE['ce_theme'] ?? 'light';
if ($theme !== 'dark' && $theme !== 'light') $theme = 'light';

if (isset($_GET['toggle_theme']) && $myU && csrf_ok()) {
    $theme = ($theme === 'dark') ? 'light' : 'dark';
    setcookie('ce_theme', $theme, time() + (86400 * 30), "/");
    header("Location: index.php");
    exit;
}

/* ---------- Режим интерфейса ---------- */
$uaRaw = $_SERVER['HTTP_USER_AGENT'] ?? '';
$themeMode = $_COOKIE['ce_theme_mode'] ?? 'auto';
if (!in_array($themeMode, ['auto','modern','classic'], true)) $themeMode = 'auto';

/* ---------- Онлайн ---------- */
if ($myU) {
    $fp = @fopen($onlineF, 'c+');
    if ($fp) {
        flock($fp, LOCK_EX);
        $content = stream_get_contents($fp);
        $lines = $content ? explode("\n", $content) : [];
        $newLines = ["<?php die(); ?>"];
        foreach ($lines as $ol) {
            if (strpos($ol, '<?php') !== false || !trim($ol)) continue;
            $od = explode('|', trim($ol));
            if (($od[0] ?? '') !== $myU && ($od[1] ?? 0) > (time() - 300)) {
                $newLines[] = trim($ol);
            }
        }
        $newLines[] = "$myU|" . time();
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, implode("\n", $newLines) . "\n");
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

/* ---------- Утилиты ---------- */
function db_append($f, $d) {
    if (!file_exists($f)) file_put_contents($f, "<?php die(); ?>\n");
    $d = str_replace(["\r", "\n"], " ", $d);
    return file_put_contents($f, $d . "\n", FILE_APPEND | LOCK_EX);
}

function v_crypt($d, $k, $mode = 'enc') {
    if ($mode == 'enc') {
        $iv = openssl_random_pseudo_bytes(16);
        $salt = openssl_random_pseudo_bytes(16);
        $msg_key = substr(hash_hmac('sha256', $salt, $k, true), 0, 16);
        $enc = openssl_encrypt($d, "aes-128-ctr", $msg_key, 0, $iv);
        return "B:" . str_replace(['+','/','='], ['-','_',''], base64_encode($iv . "::" . $salt . "::" . $enc));
    } else {
        if (substr($d, 0, 2) !== "B:") return $d;
        $raw = base64_decode(str_replace(['-','_'], ['+','/'], substr($d, 2)));
        $p = explode("::", $raw);
        $iv = $p[0] ?? ''; $salt = $p[1] ?? ''; $enc = $p[2] ?? '';
        $msg_key = substr(hash_hmac('sha256', $salt, $k, true), 0, 16);
        return openssl_decrypt($enc, "aes-128-ctr", $msg_key, 0, $iv);
    }
}

function is_user_online($u) {
    global $onlineF;
    if (!file_exists($onlineF)) return false;
    foreach (file($onlineF) as $ol) {
        if (strpos($ol, '<?php') !== false) continue;
        $od = explode('|', trim($ol));
        if (($od[0] ?? '') == $u && ($od[1] ?? 0) > (time() - 300)) return true;
    }
    return false;
}

function get_avatar_html($u, $name) {
    global $avatarDir;
    $base = $avatarDir . md5($u);
    $f = null;
    foreach (['png','jpg','jpeg','gif'] as $ext) {
        if (file_exists("$base.$ext")) { $f = "$base.$ext"; break; }
    }
    $isOnline = is_user_online($u);
    $onlineBadge = $isOnline ? "<span style='position:absolute; bottom:-2px; right:-2px; width:8px; height:8px; background:#2aa198; border:2px solid white; border-radius:50%;' title='В сети'></span>" : "";

    $html = "<div style='position:relative; display:inline-block; vertical-align:middle; margin-right:5px;'>";
    if ($f) {
        $html .= "<img src='" . e($f) . "?" . filemtime($f) . "' width='24' height='24' style='border-radius:50%; display:block;'>";
    } else {
        $colors = ['#268bd2', '#b58900', '#cb4b16', '#dc322f', '#2aa198'];
        $c = $colors[abs(crc32($u)) % count($colors)];
        $l = mb_strtoupper(mb_substr($name ?? 'U', 0, 1));
        $html .= "<div style='width:24px; height:24px; border-radius:50%; background:$c; color:white; text-align:center; line-height:24px; font-size:10px;'>" . e($l) . "</div>";
    }
    return $html . $onlineBadge . "</div>";
}

function parse_msg($m, $msgID = '') {
    $m = htmlspecialchars($m, ENT_QUOTES, 'UTF-8');
    $smiles = [
        ':heart:' => 'heart.gif', ':hi:' => 'hi.gif', ':sarcasm:' => 'sarcasm.gif',
        ':cool:' => 'good.gif', ':smile:' => 'smile.gif', ':fire:' => 'fire.gif',
        '(ツ)' => 'smile.gif', '¯\_(ツ)_/¯' => 'smile.gif'
    ];
    foreach ($smiles as $code => $img) {
        $m = str_replace($code, "<img src='smiles/$img' width='18' height='18' style='vertical-align:middle;' title='" . e($code) . "'>", $m);
    }
    // Аудио
    $m = preg_replace('/\[file\](uploads\/[a-z0-9]+\.(?:amr|mp3|ogg|wav|m4a))\[\/file\]/i',
        '<br><audio controls preload="none" src="$1" class="audio-msg"></audio>', $m);
    // Картинки
    $m = preg_replace('/\[img\](uploads\/[a-z0-9]+\.(?:png|jpg|jpeg|gif))\[\/img\]/i',
        '<br><img src="$1" style="max-width:100%; border-radius:5px; margin-top:5px;">', $m);
    // Файлы
    $m = preg_replace('/\[file\](uploads\/[a-z0-9]+\.[a-z0-9]+)\[\/file\]/i',
        '<br><a href="$1" style="display:inline-block; background:#eee; padding:4px; border:1px solid #777; text-decoration:none; color:#333; font-size:10px;">Файл</a>', $m);
    // Опросы
    if ($msgID !== '') $m = parse_polls($m, $msgID);
    return nl2br($m);
}

function parse_polls($text, $msgID) {
    global $reacDir;
    return preg_replace_callback('/\[poll\](.+?)\[\/poll\]/is', function($m) use ($msgID, $reacDir) {
        $parts = explode('|', $m[1]);
        if (count($parts) < 2) return $m[0];
        $question = array_shift($parts);
        $variants = array_slice($parts, 0, 8);
        $vf = $reacDir . "poll_" . $msgID . ".db.php";
        $votes = [];
        if (file_exists($vf)) {
            foreach (file($vf) as $l) {
                if (strpos($l, '<?php') !== false || !trim($l)) continue;
                $v = explode('|', trim($l));
                if (count($v) >= 2) $votes[$v[1]][] = $v[0];
            }
        }
        $myU = $_SESSION['ce_uid'] ?? '';
        $csrf = $_SESSION['csrf'] ?? '';
        $html = '<div class="poll-box"><b>📊 ' . htmlspecialchars($question, ENT_QUOTES, 'UTF-8') . '</b>';
        $total = 0;
        foreach ($votes as $arr) $total += count($arr);
        foreach ($variants as $i => $v) {
            $cnt = isset($votes[$i]) ? count($votes[$i]) : 0;
            $pct = $total > 0 ? round(($cnt / $total) * 100) : 0;
            $voted = $myU && in_array($myU, $votes[$i] ?? [], true);
            $html .= '<a href="?vote_mid=' . urlencode($msgID) . '&poll_opt=' . $i . '&to=' . urlencode($_REQUEST['to'] ?? 'all') . '&csrf=' . urlencode($csrf) . '" class="poll-opt' . ($voted?' poll-voted':'') . '">';
            $html .= '<span class="poll-fill" style="width:' . $pct . '%;"></span>';
            $html .= '<span class="poll-text">' . htmlspecialchars($v, ENT_QUOTES, 'UTF-8') . '</span>';
            $html .= '<span class="poll-count">' . $cnt . ' (' . $pct . '%)</span>';
            $html .= '</a>';
        }
        $html .= '<div class="poll-total">Всего голосов: ' . $total . '</div>';
        $html .= '</div>';
        return $html;
    }, $text);
}

function get_last_view_time($u, $target) {
    global $unreadF;
    if (!file_exists($unreadF)) return 0;
    foreach (file($unreadF) as $l) {
        if (strpos($l, '<?php') !== false) continue;
        $d = explode('|', trim($l));
        if (($d[0] ?? '') == $u && ($d[1] ?? '') == $target) return (int)($d[2] ?? 0);
    }
    return 0;
}

function set_last_view_time($u, $target) {
    global $unreadF;
    $lines = file_exists($unreadF) ? file($unreadF) : [];
    $newLines = ["<?php die(); ?>\n"];
    foreach ($lines as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if (($d[0] ?? '') != $u || ($d[1] ?? '') != $target) $newLines[] = rtrim(trim($l), "\r\n") . "\n";
    }
    $newLines[] = "$u|$target|" . time() . "\n";
    file_put_contents($unreadF, implode("", $newLines), LOCK_EX);
}

function has_new_messages($u, $target, $file_path) {
    if (!file_exists($file_path)) return false;
    $last_view = get_last_view_time($u, $target);
    if (filemtime($file_path) <= $last_view) return false;
    foreach (file($file_path) as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if (($d[3] ?? '') != $u) return true;
    }
    return false;
}

function count_unread($u, $target, $file_path) {
    if (!file_exists($file_path)) return 0;
    $last = get_last_view_time($u, $target);
    if (filemtime($file_path) <= $last) return 0;
    $n = 0;
    foreach (file($file_path) as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if (($d[3] ?? '') !== $u) $n++;
    }
    return $n;
}

function get_last_seen($u) {
    global $onlineF;
    if (!file_exists($onlineF)) return 0;
    $max = 0;
    foreach (file($onlineF) as $ol) {
        if (strpos($ol, '<?php') !== false) continue;
        $od = explode('|', trim($ol));
        if (($od[0] ?? '') === $u) {
            $t = (int)($od[1] ?? 0);
            if ($t > $max) $max = $t;
        }
    }
    return $max;
}

function human_last_seen($t) {
    if ($t <= 0) return 'давно';
    $diff = time() - $t;
    if ($diff < 300)     return 'в сети';
    if ($diff < 3600)    return floor($diff/60) . ' мин назад';
    if ($diff < 86400)   return floor($diff/3600) . ' ч назад';
    if ($diff < 172800)  return 'вчера в ' . date('H:i', $t);
    if ($diff < 604800)  return floor($diff/86400) . ' дн назад';
    return date('d.m.Y', $t);
}

function is_subscribed($uid, $gid) {
    global $rDir;
    $f = $rDir . "subs_" . $gid . ".db.php";
    if (!file_exists($f)) return false;
    foreach (file($f) as $l) {
        if (strpos($l, '<?php') !== false) continue;
        if (trim($l) === $uid) return true;
    }
    return false;
}

function toggle_subscribe($uid, $gid, $on) {
    global $rDir;
    $f = $rDir . "subs_" . $gid . ".db.php";
    $lines = file_exists($f) ? file($f) : [];
    $newLines = ["<?php die(); ?>\n"];
    $found = false;
    foreach ($lines as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        if (trim($l) === $uid) { $found = true; if (!$on) continue; }
        $newLines[] = rtrim(trim($l), "\r\n") . "\n";
    }
    if ($on && !$found) $newLines[] = $uid . "\n";
    file_put_contents($f, implode("", $newLines), LOCK_EX);
}

function get_subs_count($gid) {
    global $rDir;
    $f = $rDir . "subs_" . $gid . ".db.php";
    if (!file_exists($f)) return 0;
    $n = 0;
    foreach (file($f) as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $n++;
    }
    return $n;
}

function my_groups($uid) {
    global $groupsF;
    $out = [];
    if (!file_exists($groupsF)) return $out;
    foreach (file($groupsF) as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $g = explode('|', trim($l));
        if (count($g) < 4) continue;
        $gid = $g[0];
        $isOwner = ($g[3] === $uid);
        $isSub   = is_subscribed($uid, $gid);
        if ($isOwner || $isSub) {
            $out[] = ['id'=>$gid, 'name'=>$g[1], 'type'=>$g[2], 'owner'=>$g[3], 'subs'=>get_subs_count($gid)];
        }
    }
    return $out;
}

function total_unread_pm($myU) {
    global $rDir;
    $total = 0;
    $dir = opendir($rDir);
    if (!$dir) return 0;
    while (($f = readdir($dir)) !== false) {
        if (strpos($f, 'pm_') !== 0 || substr($f, -8) !== '.db.php') continue;
        $room = substr($f, 0, -8);
        $parts = explode('_', substr($room, 3));
        if (!in_array($myU, $parts, true)) continue;
        $total += count_unread($myU, $room, $rDir . $f);
    }
    closedir($dir);
    return $total;
}

/* ---------- UA ---------- */
function ua_parse($ua) {
    $ua = (string)$ua;
    $os = 'Неизвестно'; $browser = 'Неизвестно'; $device = 'Компьютер';

    if (preg_match('/Windows NT 10/i', $ua))       $os = 'Windows 10/11';
    elseif (preg_match('/Windows NT 6\.3/i', $ua)) $os = 'Windows 8.1';
    elseif (preg_match('/Windows NT 6\.1/i', $ua)) $os = 'Windows 7';
    elseif (preg_match('/Windows/i', $ua))         $os = 'Windows';
    elseif (preg_match('/Android[ \/]([0-9\.]+)/i', $ua, $m)) $os = 'Android ' . $m[1];
    elseif (preg_match('/iPhone|iPad|iPod/i', $ua)) $os = 'iOS';
    elseif (preg_match('/Mac OS X/i', $ua))         $os = 'macOS';
    elseif (preg_match('/Linux/i', $ua))            $os = 'Linux';
    elseif (preg_match('/Dorado/i', $ua))            $os = 'Mocor OS';

    if (preg_match('/Opera Mini/i', $ua))           $browser = 'Opera Mini';
    elseif (preg_match('/OPR\/([0-9\.]+)/i', $ua, $m)) $browser = 'Opera ' . $m[1];
    elseif (preg_match('/Edg\/([0-9\.]+)/i', $ua, $m)) $browser = 'Edge ' . $m[1];
    elseif (preg_match('/Chrome\/([0-9\.]+)/i', $ua, $m) && !preg_match('/OPR|Edg/i', $ua)) $browser = 'Chrome ' . $m[1];
    elseif (preg_match('/Firefox\/([0-9\.]+)/i', $ua, $m)) $browser = 'Firefox ' . $m[1];
    elseif (preg_match('/Version\/([0-9\.]+).*Safari/i', $ua, $m)) $browser = 'Safari ' . $m[1];
    elseif (preg_match('/MSIE ([0-9\.]+)/i', $ua, $m)) $browser = 'IE ' . $m[1];

    if (preg_match('/Mobile|Android|iPhone|iPod|Opera Mini|IEMobile/i', $ua)) $device = 'Телефон';
    if (preg_match('/iPad|Tablet/i', $ua)) $device = 'Планшет';
    if (preg_match('/SmartTV|TV|NetCast/i', $ua)) $device = 'ТВ';

    return ['os' => $os, 'browser' => $browser, 'device' => $device];
}

function ua_is_modern($ua) {
    $ua = (string)$ua;
    if ($ua === '') return false;
    if (preg_match('/Android[ \/]([0-9]+)/i', $ua, $m)) {
        if ((int)$m[1] < 7) return false;
    }
    if (preg_match('/iPhone OS ([0-9]+)/i', $ua, $m) || preg_match('/CPU OS ([0-9]+)/i', $ua, $m)) {
        if ((int)$m[1] < 13) return false;
    }
    if (preg_match('/(?:Chrome|Chromium|CriOS)\/([0-9]+)/i', $ua, $m)) return (int)$m[1] >= 51;
    if (preg_match('/OPR\/([0-9]+)/i', $ua, $m)) return (int)$m[1] >= 38;
    if (preg_match('/Edg\/([0-9]+)/i', $ua, $m)) return (int)$m[1] >= 79;
    if (preg_match('/Firefox\/([0-9]+)/i', $ua, $m)) return (int)$m[1] >= 54;
    if (preg_match('/Version\/([0-9]+).*Safari/i', $ua, $m)) return (int)$m[1] >= 10;
    if (preg_match('/Opera Mini|MSIE|Trident/i', $ua)) return false;
    return false;
}

if ($themeMode === 'modern')       $uiMode = 'modern';
elseif ($themeMode === 'classic')  $uiMode = 'classic';
else                               $uiMode = ua_is_modern($uaRaw) ? 'modern' : 'classic';

/* ---------- Лог входов ---------- */
function log_login($uid, $status = 'ok') {
    global $loginsF;
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300);
    $info = ua_parse($ua);
    $line = implode('|', [$uid, time(), $info['device'], $info['os'], $info['browser'], $status, str_replace('|', ' ', $ua)]);
    db_append($loginsF, $line);
}

function get_login_log($uid, $limit = 30) {
    global $loginsF;
    if (!file_exists($loginsF)) return [];
    $out = [];
    $lines = file($loginsF);
    for ($i = count($lines) - 1; $i >= 0 && count($out) < $limit; $i--) {
        $l = $lines[$i];
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if (($d[0] ?? '') !== $uid) continue;
        $out[] = ['time'=>(int)($d[1]??0),'device'=>$d[2]??'?','os'=>$d[3]??'?','browser'=>$d[4]??'?','status'=>$d[5]??'ok','ua'=>$d[6]??''];
    }
    return $out;
}

/* ---------- Валидация ---------- */
$to = strtolower(preg_replace('/[^a-zA-Z0-9_]/', '', $_REQUEST['to'] ?? 'all'));
if ($to === '') $to = 'all';
if ($to === 'saved' && $myU) $to = "saved_" . $myU;

$allowed_views = [
    'chat','digest','choose_reac','mods_page','dev_info','eula','license',
    'run_mod','edit_mod','search','profile','edit','groups','contacts',
    'settings','logins'
];
$view = preg_replace('/[^a-z_]/', '', $_GET['view'] ?? 'chat');
if (!in_array($view, $allowed_views, true)) $view = 'chat';

function resolve_chat_file($to, $myU) {
    global $rDir;
    if ($to === 'all') return $rDir . "global.db.php";
    if (strpos($to, 'saved_') === 0) {
        if ($to !== 'saved_' . $myU) return null;
        return $rDir . "$to.db.php";
    }
    if (strpos($to, 'pm_') === 0) {
        $rest = substr($to, 3);
        $parts = explode('_', $rest);
        if (count($parts) < 2) return null;
        if (!in_array($myU, $parts, true)) return null;
        return $rDir . "$to.db.php";
    }
    if (strpos($to, 'group_') === 0) {
        $gid = preg_replace('/[^a-z0-9]/', '', substr($to, 6));
        if ($gid === '') return null;
        return $rDir . "group_$gid.db.php";
    }
    if (strpos($to, 'gb_') === 0) {
        $mid = preg_replace('/[^a-z0-9]/', '', substr($to, 3));
        if ($mid === '') return null;
        return $rDir . "gb_$mid.db.php";
    }
    return $rDir . "room_$to.db.php";
}

$curF = resolve_chat_file($to, $myU);

if ($myU && $view === 'chat' && $curF) set_last_view_time($myU, $to);

/* ---------- Экспорт ---------- */
if (isset($_GET['export']) && $myU && $curF && file_exists($curF) && csrf_ok()) {
    $fmt = $_GET['export'];
    $baseName = "history_{$to}_" . date('Y-m-d');

    $rows = [];
    foreach (file($curF) as $l) {
        if (strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        $rows[] = [
            'time'  => $d[2] ?? '',
            'uid'   => $d[3] ?? '',
            'name'  => $d[0] ?? '',
            'text'  => v_crypt($d[1] ?? '', $crypto_key, 'dec'),
        ];
    }

    if ($fmt === 'json') {
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $baseName . '.json"');
        echo json_encode(['room'=>$to,'exported_at'=>date('c'),'count'=>count($rows),'messages'=>$rows], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    if ($fmt === 'html') {
        header('Content-Type: text/html; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $baseName . '.html"');
        echo "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Экспорт $to</title>";
        echo "<style>body{font-family:sans-serif;max-width:800px;margin:20px auto;padding:10px;background:#fdf6e3;color:#073642;}";
        echo ".msg{border-bottom:1px solid #eae1c8;padding:8px 0;}.meta{font-size:11px;color:#888;}b.nick{color:#268bd2;}</style></head><body>";
        echo "<h1>Комната: " . htmlspecialchars($to, ENT_QUOTES, 'UTF-8') . "</h1>";
        echo "<p>Экспортировано: " . date('d.m.Y H:i') . ". Сообщений: " . count($rows) . "</p><hr>";
        foreach ($rows as $r) {
            echo "<div class='msg'><b class='nick'>" . htmlspecialchars($r['name'], ENT_QUOTES, 'UTF-8') . "</b> ";
            echo "<span class='meta'>" . htmlspecialchars($r['time'], ENT_QUOTES, 'UTF-8') . "</span><br>";
            echo parse_msg($r['text']);
            echo "</div>";
        }
        echo "</body></html>";
        exit;
    }

    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $baseName . '.txt"');
    foreach ($rows as $r) {
        $plainTxt = strip_tags(str_replace(['[img]','[/img]','[file]','[/file]'], ' ', $r['text']));
        echo "[{$r['time']}] {$r['name']}: {$plainTxt}\r\n";
    }
    exit;
}

/* ---------- Удаление ---------- */
if (isset($_GET['del_msg']) && $myU && $curF && csrf_ok()) {
    $target_mid = preg_replace('/[^a-z0-9]/', '', $_GET['del_msg']);
    if (file_exists($curF)) {
        $lines = file($curF); $newLines = [];
        foreach ($lines as $l) {
            if (strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
            if (md5(trim($l)) == $target_mid) {
                $d = explode('|', trim($l));
                if (($d[3] ?? '') == $myU || $myU == $adminID) {
                    $newLines[] = "{$d[0]}|" . v_crypt("[Сообщение удалено]", $crypto_key) . "|{$d[2]}|{$d[3]}|1\n";
                    continue;
                }
            }
            $newLines[] = $l;
        }
        file_put_contents($curF, implode("", $newLines), LOCK_EX);
    }
    header("Location: ?view=chat&to=" . urlencode($to)); exit;
}

/* ---------- Редактирование ---------- */
if (isset($_POST['edit_msg']) && $myU && $curF && csrf_ok()) {
    $target_mid = preg_replace('/[^a-z0-9]/', '', $_POST['mid']);
    $new_text = $_POST['new_text'] ?? '';
    if (file_exists($curF) && $new_text) {
        $lines = file($curF); $newLines = [];
        foreach ($lines as $l) {
            if (strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
            if (md5(trim($l)) == $target_mid) {
                $d = explode('|', trim($l));
                if (($d[3] ?? '') == $myU) {
                    $newLines[] = "{$d[0]}|" . v_crypt($new_text, $crypto_key) . "|{$d[2]}|{$d[3]}|1\n";
                    continue;
                }
            }
            $newLines[] = $l;
        }
        file_put_contents($curF, implode("", $newLines), LOCK_EX);
    }
    header("Location: ?view=chat&to=" . urlencode($to)); exit;
}

/* ---------- Реакции ---------- */
if (isset($_GET['add_reac_id']) && $myU && csrf_ok()) {
    $mid = preg_replace('/[^a-z0-9]/', '', $_GET['add_reac_id']);
    $type = preg_replace('/[^a-z0-9\.]/', '', $_GET['type']);
    $allowed_reac = ['fire.gif','smile.gif','good.gif','heart.gif','hi.gif','sarcasm.gif'];
    if ($mid !== '' && in_array($type, $allowed_reac, true)) {
        $rf = $reacDir . $mid . ".db.php";
        $already = false;
        if (file_exists($rf)) {
            foreach (file($rf) as $line) if (strpos($line, "$myU|$type") !== false) $already = true;
        }
        if (!$already) db_append($rf, "$myU|$myN|$type");
    }
    header("Location: ?view=chat&to=" . urlencode($to) . "#msg_$mid"); exit;
}

/* ---------- Голосование ---------- */
if (isset($_GET['vote_mid']) && $myU && csrf_ok()) {
    $mid = preg_replace('/[^a-z0-9]/', '', $_GET['vote_mid']);
    $opt = (int)($_GET['poll_opt'] ?? -1);
    if ($mid !== '' && $opt >= 0 && $opt < 20) {
        $vf = $reacDir . "poll_" . $mid . ".db.php";
        $lines = file_exists($vf) ? file($vf) : [];
        $newLines = ["<?php die(); ?>\n"];
        $already = false;
        foreach ($lines as $l) {
            if (strpos($l, '<?php') !== false || !trim($l)) continue;
            $v = explode('|', trim($l));
            if (($v[0] ?? '') === $myU) { $newLines[] = "$myU|$opt\n"; $already = true; }
            else $newLines[] = rtrim(trim($l), "\r\n") . "\n";
        }
        if (!$already) $newLines[] = "$myU|$opt\n";
        file_put_contents($vf, implode("", $newLines), LOCK_EX);
    }
    header("Location: ?view=chat&to=" . urlencode($to) . "#msg_$mid"); exit;
}

/* ---------- Подписки ---------- */
if (isset($_GET['sub']) && $myU && csrf_ok()) {
    $gid = preg_replace('/[^a-z0-9]/', '', $_GET['sub']);
    $action = $_GET['do'] ?? 'on';
    if ($gid !== '') toggle_subscribe($myU, $gid, $action === 'on');
    header("Location: ?view=chat&to=group_" . urlencode($gid)); exit;
}

/* ---------- Заявка в контакты ---------- */
if (isset($_GET['add_c']) && $myU && csrf_ok()) {
    $cid = preg_replace('/[^a-z0-9]/', '', $_GET['add_c']);
    if ($cid !== '' && $cid != $myU) {
        $already = false;
        if (file_exists($reqF)) {
            foreach (file($reqF) as $l) {
                if (strpos($l, '<?php') !== false) continue;
                $d = explode('|', trim($l));
                if (($d[0] ?? '') == $myU && ($d[1] ?? '') == $cid) { $already = true; break; }
            }
        }
        if (!$already) db_append($reqF, "$myU|$cid|$myN");
    }
    header("Location: ?view=profile&uid=" . urlencode($cid)); exit;
}

/* ---------- Обработка заявок ---------- */
if (isset($_GET['req_action']) && $myU && csrf_ok()) {
    $from_uid = preg_replace('/[^a-z0-9]/', '', $_GET['from_uid']);
    $action = $_GET['req_action'];
    if ($from_uid !== '' && in_array($action, ['accept','reject'], true)) {
        if (file_exists($reqF)) {
            $lines = file($reqF); $newLines = ["<?php die(); ?>\n"];
            $sender_name = $from_uid;
            foreach ($lines as $l) {
                if (strpos($l, '<?php') !== false || !trim($l)) continue;
                $d = explode('|', trim($l));
                if (($d[0] ?? '') == $from_uid && ($d[1] ?? '') == $myU) {
                    if (isset($d[2])) $sender_name = trim($d[2]);
                    continue;
                }
                $newLines[] = rtrim(trim($l), "\r\n") . "\n";
            }
            file_put_contents($reqF, implode("", $newLines), LOCK_EX);
            if ($action === 'accept') {
                db_append($rDir . "contacts_" . $myU . ".db.php", "$from_uid|$sender_name");
                db_append($rDir . "contacts_" . $from_uid . ".db.php", "$myU|$myN");
            }
        }
    }
    header("Location: ?view=digest"); exit;
}

/* ---------- Профиль ---------- */
if (isset($_POST['up_profile']) && $myU && csrf_ok()) {
    if (!empty($_FILES['ava_file']['tmp_name'])) {
        $check = @getimagesize($_FILES['ava_file']['tmp_name']);
        $ext = strtolower(pathinfo($_FILES['ava_file']['name'], PATHINFO_EXTENSION));
        if ($check !== false && in_array($ext, ['png','jpg','jpeg','gif'])) {
            foreach (['png','jpg','jpeg','gif'] as $e2) @unlink($avatarDir . md5($myU) . '.' . $e2);
            move_uploaded_file($_FILES['ava_file']['tmp_name'], $avatarDir . md5($myU) . '.' . $ext);
        }
    }
    if (isset($_POST['about'])) {
        $about_safe = str_replace(["\r", "\n", "|"], " ", (string)$_POST['about']);
        $about_safe = mb_substr($about_safe, 0, 500);
        file_put_contents($avatarDir . md5($myU) . '.txt', $about_safe);
    }
    header("Location: ?view=profile"); exit;
}

/* ---------- Настройки ---------- */
if (isset($_POST['save_settings']) && $myU && csrf_ok()) {
    $errors = [];

    if (isset($_POST['new_nick'])) {
        $newN = str_replace(['|', '?', '<', '>', '"', "'", "\r", "\n"], '', (string)$_POST['new_nick']);
        $newN = mb_substr(trim($newN), 0, 32);
        if ($newN !== '' && $newN !== $myN) {
            $lines = file($passF); $newLines = [];
            foreach ($lines as $l) {
                if (strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
                $d = explode('|', trim($l));
                if (($d[0] ?? '') == $myU) { $d[2] = $newN; $newLines[] = implode('|', $d) . "\n"; }
                else $newLines[] = $l;
            }
            file_put_contents($passF, implode('', $newLines), LOCK_EX);
            $_SESSION['ce_nick'] = $newN;
            $myN = $newN;
        }
    }

    if (!empty($_POST['new_pwd'])) {
        $oldP = (string)($_POST['old_pwd'] ?? '');
        $newP = (string)$_POST['new_pwd'];
        $newP2 = (string)($_POST['new_pwd2'] ?? '');
        if (mb_strlen($newP) < 4) $errors[] = "Новый пароль слишком короткий.";
        elseif ($newP !== $newP2) $errors[] = "Пароли не совпадают.";
        else {
            $ok = false;
            foreach (file($passF) as $l) {
                if (strpos($l, '<?php') !== false) continue;
                $d = explode('|', trim($l));
                if (($d[0] ?? '') == $myU && password_verify($oldP, $d[1])) { $ok = true; break; }
            }
            if (!$ok) $errors[] = "Текущий пароль неверен.";
            else {
                $lines = file($passF); $newLines = [];
                foreach ($lines as $l) {
                    if (strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
                    $d = explode('|', trim($l));
                    if (($d[0] ?? '') == $myU) { $d[1] = password_hash($newP, PASSWORD_DEFAULT); $newLines[] = implode('|', $d) . "\n"; }
                    else $newLines[] = $l;
                }
                file_put_contents($passF, implode('', $newLines), LOCK_EX);
                log_login($myU, 'pwd_change');
                $_SESSION['ce_msg'] = "Пароль изменён.";
            }
        }
    }

    if (isset($_POST['theme']) && in_array($_POST['theme'], ['light','dark'], true)) {
        setcookie('ce_theme', $_POST['theme'], time() + (86400 * 30), "/");
        $theme = $_POST['theme'];
    }
    if (isset($_POST['ui_mode']) && in_array($_POST['ui_mode'], ['auto','modern','classic'], true)) {
        setcookie('ce_theme_mode', $_POST['ui_mode'], time() + (86400 * 30), "/");
        $themeMode = $_POST['ui_mode'];
        if ($themeMode === 'modern')       $uiMode = 'modern';
        elseif ($themeMode === 'classic')  $uiMode = 'classic';
        else                               $uiMode = ua_is_modern($uaRaw) ? 'modern' : 'classic';
    }

    if ($errors) $_SESSION['ce_error'] = implode(' ', $errors);
    elseif (empty($_SESSION['ce_msg'])) $_SESSION['ce_msg'] = "Настройки сохранены.";

    header("Location: ?view=settings"); exit;
}

/* ---------- Создание комнаты ---------- */
if (isset($_POST['create_room']) && $myU && csrf_ok()) {
    $name = str_replace('|', '-', (string)$_POST['r_name']);
    $name = mb_substr($name, 0, 60);
    $type = (($_POST['r_type'] ?? '') === 'channel') ? 'channel' : 'group';
    $id = bin2hex(openssl_random_pseudo_bytes(4));
    db_append($groupsF, "$id|$name|$type|$myU");
    toggle_subscribe($myU, $id, true);
    header("Location: ?view=groups"); exit;
}

/* ---------- Авторизация ---------- */
if (isset($_POST['login']) || isset($_POST['register'])) {
    $u = strtolower(preg_replace('/[^a-z0-9]/', '', $_POST['u_id'] ?? ''));
    $p = $_POST['pwd'] ?? '';
    $rawN = (string)($_POST['dn'] ?? $u);
    $n = str_replace(['|', '?', '<', '>', '"', "'", "\r", "\n"], '', $rawN);
    $n = mb_substr(trim($n), 0, 32);
    if ($n === '') $n = $u;

    if ($u && $p) {
        $exists = false; $auth = false; $storedN = $u;
        if (file_exists($passF)) {
            foreach (file($passF) as $l) {
                if (strpos($l, '<?php') !== false) continue;
                $d = explode('|', trim($l));
                if (($d[0] ?? '') == $u) {
                    $exists = true;
                    if (password_verify($p, $d[1])) { $auth = true; $storedN = $d[2] ?? $u; }
                    break;
                }
            }
        }
        if (isset($_POST['register'])) {
            if ($exists) $_SESSION['ce_error'] = "Логин занят!";
            else {
                db_append($passF, "$u|" . password_hash($p, PASSWORD_DEFAULT) . "|$n");
                session_regenerate_id(true);
                $_SESSION['ce_uid'] = $u;
                $_SESSION['ce_nick'] = $n;
                log_login($u, 'register');
                header("Location: index.php"); exit;
            }
        } else {
            if ($auth) {
                session_regenerate_id(true);
                $_SESSION['ce_uid'] = $u;
                $_SESSION['ce_nick'] = $storedN;
                log_login($u, 'ok');
                header("Location: index.php"); exit;
            } else {
                log_login($u, 'fail');
                $_SESSION['ce_error'] = "Неверный логин или пароль!";
            }
        }
    }
}

if (isset($_GET['logout']) && csrf_ok()) {
    $_SESSION = [];
    session_destroy();
    header("Location: index.php"); exit;
}

/* ---------- Отправка сообщений ---------- */
if ($myU && isset($_POST['send_msg']) && csrf_ok() && $curF) {
    $isChannel = false; $channelOwner = ''; $isGuestbook = false;
    if (strpos($to, 'group_') === 0) {
        $r_id = str_replace('group_', '', $to);
        if (file_exists($groupsF)) {
            foreach (file($groupsF) as $gl) {
                $gd = explode('|', trim($gl));
                if (($gd[0] ?? '') == $r_id && ($gd[2] ?? '') === 'channel') { $isChannel = true; $channelOwner = $gd[3] ?? ''; break; }
            }
        }
    }
    if (strpos($to, 'gb_') === 0) $isGuestbook = true;

    if (($isChannel && !$isGuestbook && $channelOwner !== $myU)) {
        header("Location: ?view=chat&to=" . urlencode($to)); exit;
    }

    $m = $_POST['msg'] ?? '';
    $fT = ""; $isValidFile = true;
    if (!empty($_FILES['f']['name'])) {
        $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
        $allowedExtensions = ['jpg','png','gif','jpeg','zip','rar','txt','amr','mp3','ogg','wav','m4a'];
        $isImageExt = in_array($ext, ['jpg','png','gif','jpeg']);
        if (!in_array($ext, $allowedExtensions, true)) $isValidFile = false;
        if ($isImageExt && $isValidFile) {
            if (@getimagesize($_FILES['f']['tmp_name']) === false) $isValidFile = false;
        }
        if ($isValidFile) {
            $nf = bin2hex(openssl_random_pseudo_bytes(8)) . '.' . $ext;
            if (move_uploaded_file($_FILES['f']['tmp_name'], $up . $nf)) {
                $fT = $isImageExt ? "[img]" . $up . $nf . "[/img]" : "[file]" . $up . $nf . "[/file]";
            }
        }
    }
    if (($m || $fT) && $isValidFile) {
        $safeMyN = str_replace(['|', "\n", "\r"], '', $myN);
        db_append($curF, "$safeMyN|" . v_crypt($m . ($m && $fT ? " " : "") . $fT, $crypto_key) . "|" . date('H:i') . "|$myU|0");
    }
    header("Location: ?view=" . urlencode($view) . "&to=" . urlencode($to)); exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CrossEra Messenger</title>

    <!-- PWA -->
    <link rel="manifest" href="manifest.json">
    <meta name="theme-color" content="#a01ae8">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <link rel="apple-touch-icon" href="icon-192.png">

    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        html, body { height:100%; width:100%; }

        body.theme-light { background:#fdf6e3; color:#657b83; }
        body.theme-light .box { background:#eee8d5; color:#073642; }
        body.theme-light #chat, body.theme-light .main-panel { background:#fdf6e3; color:#586e75; }
        body.theme-light .m { border-bottom:1px solid #eae1c8; }
        body.theme-light .mod-card { background:#eee8d5; border:1px solid #d3cbb7; color:#073642; }

        body.theme-dark { background:#073642; color:#93a1a1; }
        body.theme-dark .box { background:#002b36; color:#93a1a1; }
        body.theme-dark #chat, body.theme-dark .main-panel { background:#002b36; color:#839496; }
        body.theme-dark .m { border-bottom:1px solid #073642; }
        body.theme-dark .mod-card { background:#073642; border:1px solid #586e75; color:#93a1a1; }
        body.theme-dark textarea, body.theme-dark input[type="text"], body.theme-dark input[type="password"] { background:#073642; color:#eee; border:1px solid #586e75; }

        body { font-family:sans-serif; font-size:12px; }

        .box { width:100%; min-height:100%; display:block; position:relative; }
        .hdr { background:#a01ae8; color:white; padding:10px; font-weight:bold; }
        .nav { background:#93a1a1; padding:5px; border-bottom:1px solid #586e75; }
        body.theme-dark .nav { background:#073642; border-bottom:1px solid #586e75; }
        .nav a { background:#eee; color:#000; text-decoration:none; padding:4px 8px; font-size:10px; border:1px solid #666; border-radius:3px; display:inline-block; margin:2px 1px; }
        .nav a.active { background:#2aa198; color:white; }

        .content { width:100%; display:block; padding-bottom:120px; }
        #chat, .main-panel { padding:10px; display:block; }

        .m { padding:8px 0; position:relative; }
        .btn { background:#2aa198; color:white; border:none; padding:4px 10px; cursor:pointer; text-decoration:none; font-size:11px; border-radius:3px; display:inline-block; }
        .mod-card { padding:10px; margin-bottom:8px; border-radius:5px; position:relative; }

        .reac-bar { margin-left:29px; margin-top:4px; display:block; }
        .reac-btn { background:#f0f0f0; border:1px solid #ccc; border-radius:10px; padding:1px 4px; font-size:9px; text-decoration:none; color:#333; display:inline-block; margin-right:3px; vertical-align:middle; }
        body.theme-dark .reac-btn { background:#2a2a2a; border:1px solid #444; color:#ccc; }

        .reac-label { background:#f0f0f0; border:1px solid #ccc; border-radius:10px; padding:1px 8px; font-size:9px; color:#333; cursor:pointer; display:inline-block; text-decoration:none; vertical-align:middle; user-select:none; }
        body.theme-dark .reac-label { background:#2a2a2a; border:1px solid #444; color:#ccc; }

        .err-msg { background:#dc322f; color:white; padding:8px; margin-bottom:10px; text-align:center; font-weight:bold; }
        .fast-reply { background:#eee; border:1px solid #ccc; padding:2px 5px; font-size:10px; text-decoration:none; color:#000; border-radius:3px; display:inline-block; }
        body.theme-dark .fast-reply { background:#333; border-color:#555; color:#fff; }

        .chat-form-fixed { position:fixed; bottom:0; left:0; width:100%; background:#eee; border-top:1px solid #ccc; padding:6px; z-index:100; }
        body.theme-dark .chat-form-fixed { background:#002b36; border-top:1px solid #586e75; }

        /* ---------- Опросы ---------- */
        .poll-box { background:rgba(0,0,0,0.03); border-radius:10px; padding:10px; margin-top:6px; font-size:12px; }
        body.theme-dark .poll-box { background:rgba(255,255,255,0.04); }
        .poll-opt { display:flex; align-items:center; position:relative; padding:5px 10px; margin:4px 0; border-radius:8px; text-decoration:none; color:inherit; background:rgba(0,0,0,0.05); overflow:hidden; transition:background .15s ease; }
        body.theme-dark .poll-opt { background:rgba(255,255,255,0.05); }
        .poll-opt:hover { background:rgba(42,161,152,0.15); }
        .poll-opt.poll-voted { outline:2px solid #2aa198; }
        .poll-fill { position:absolute; left:0; top:0; bottom:0; background:rgba(42,161,152,0.18); border-radius:8px; transition:width .35s ease; z-index:0; }
        .poll-text { position:relative; z-index:1; flex:1; }
        .poll-count { position:relative; z-index:1; font-size:11px; opacity:0.7; margin-left:8px; }
        .poll-total { font-size:10px; opacity:0.6; margin-top:4px; }

        /* ============================================================
           СОВРЕМЕННЫЙ РЕЖИМ
           ============================================================ */

        body.ui-modern { font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }

        body.ui-modern .hdr {
            background: linear-gradient(135deg, #a01ae8 0%, #6a00b8 100%);
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }

        body.ui-modern .nav { backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); }
        body.ui-modern.theme-dark .nav { background: rgba(0,43,54,0.85); }

        body.ui-modern .nav a {
            border-radius: 12px; border: 0;
            background: rgba(255,255,255,0.7);
            transition: transform .15s ease, background .15s ease, box-shadow .15s ease;
            box-shadow: 0 1px 2px rgba(0,0,0,0.06);
        }
        body.ui-modern.theme-dark .nav a { background: rgba(255,255,255,0.08); color: #eee; }
        body.ui-modern .nav a:hover { transform: translateY(-1px); box-shadow: 0 3px 6px rgba(0,0,0,0.12); }
        body.ui-modern .nav a.active {
            background: linear-gradient(135deg, #2aa198, #268bd2);
            color: #fff;
            box-shadow: 0 3px 8px rgba(42,161,152,0.35);
        }

        body.ui-modern .btn {
            border-radius: 20px; padding: 6px 14px; font-weight: 600;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: transform .12s ease, box-shadow .12s ease, filter .12s ease;
        }
        body.ui-modern .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 10px rgba(0,0,0,0.15); filter: brightness(1.05); }
        body.ui-modern .btn:active { transform: translateY(0); box-shadow: 0 1px 2px rgba(0,0,0,0.15); }

        body.ui-modern .mod-card {
            border-radius: 12px; box-shadow: 0 2px 6px rgba(0,0,0,0.08);
            transition: transform .15s ease, box-shadow .15s ease;
        }
        body.ui-modern .mod-card:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(0,0,0,0.12); }

        body.ui-modern .m {
            border-radius: 12px; padding: 10px; margin: 4px 0;
            border-bottom: 0; transition: background .15s ease;
            animation: msgIn .25s ease-out;
        }
        body.ui-modern .m:hover { background: rgba(0,0,0,0.03); }
        body.ui-modern.theme-dark .m:hover { background: rgba(255,255,255,0.04); }

        @keyframes msgIn {
            from { opacity: 0; transform: translateY(6px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        body.ui-modern .reac-btn,
        body.ui-modern .reac-label {
            border-radius: 14px; padding: 2px 8px;
            transition: transform .12s ease, background .12s ease;
        }
        body.ui-modern .reac-btn:hover,
        body.ui-modern .reac-label:hover { transform: scale(1.08); }

        body.ui-modern .fast-reply { border-radius: 14px; transition: transform .12s ease, background .12s ease; }
        body.ui-modern .fast-reply:hover { transform: translateY(-1px); background: #2aa198; color: #fff; }

        body.ui-modern .chat-form-fixed {
            backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
            box-shadow: 0 -4px 16px rgba(0,0,0,0.08);
        }

        body.ui-modern .err-msg { border-radius: 10px; animation: shake .3s ease; }
        @keyframes shake {
            0%,100% { transform: translateX(0); }
            25%     { transform: translateX(-4px); }
            75%     { transform: translateX(4px); }
        }

        body.ui-modern input[type="text"],
        body.ui-modern input[type="password"],
        body.ui-modern textarea {
            border-radius: 10px; border: 1px solid rgba(0,0,0,0.15);
            transition: border-color .15s ease, box-shadow .15s ease;
        }
        body.ui-modern.theme-dark input[type="text"],
        body.ui-modern.theme-dark input[type="password"],
        body.ui-modern.theme-dark textarea { border: 1px solid #586e75; }
        body.ui-modern input[type="text"]:focus,
        body.ui-modern input[type="password"]:focus,
        body.ui-modern textarea:focus {
            outline: none; border-color: #2aa198;
            box-shadow: 0 0 0 3px rgba(42,161,152,0.25);
        }

        body.ui-modern .mod-card { animation: cardIn .3s ease-out; }
        @keyframes cardIn {
            from { opacity: 0; transform: translateY(8px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        /* Реакции — попап */
        body.ui-modern .reac-bar { position: relative; }
        body.ui-modern .reac-popup { position: absolute; bottom: 100%; left: 0; margin-bottom: 6px; z-index: 200; animation: reacPop .18s ease-out; }
        body.ui-modern .reac-popup[hidden] { display: none; }
        body.ui-modern .reac-popup-inner {
            display: flex; gap: 4px; background: #fff; padding: 6px 8px; border-radius: 24px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.18), 0 2px 4px rgba(0,0,0,0.1);
            border: 1px solid rgba(0,0,0,0.06);
        }
        body.ui-modern.theme-dark .reac-popup-inner { background: #073642; border-color: #586e75; box-shadow: 0 6px 20px rgba(0,0,0,0.5); }
        body.ui-modern .reac-popup-btn {
            display: inline-flex; align-items: center; justify-content: center;
            width: 32px; height: 32px; border-radius: 50%; text-decoration: none;
            transition: transform .15s ease, background .15s ease;
        }
        body.ui-modern .reac-popup-btn:hover { transform: scale(1.25); background: rgba(42,161,152,0.15); }
        body.ui-modern .reac-popup-btn img { display: block; width: 20px; height: 20px; }

        @keyframes reacPop {
            from { opacity: 0; transform: translateY(6px) scale(0.9); }
            to   { opacity: 1; transform: translateY(0)   scale(1);   }
        }
        body.ui-modern.js-on .reac-trigger {
            cursor: pointer;
            background: linear-gradient(135deg, #2aa198, #268bd2);
            color: #fff; border: 0; font-weight: 700; padding: 3px 10px;
        }

        /* Аудио */
        body.ui-modern .audio-msg {
            width: 100%; max-width: 320px; margin-top: 4px;
            height: 36px; border-radius: 20px;
            background: rgba(0,0,0,0.04);
        }
        body.ui-modern.theme-dark .audio-msg { background: rgba(255,255,255,0.06); }

        /* Смайлик-пикер */
        body.ui-modern .emoji-bar {
            display: none; flex-wrap: wrap; gap: 2px;
            background: #fff; border: 1px solid rgba(0,0,0,0.08);
            border-radius: 12px; padding: 6px; margin-bottom: 6px;
            max-height: 140px; overflow-y: auto;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        body.ui-modern.theme-dark .emoji-bar { background: #073642; border-color: #586e75; }
        body.ui-modern .emoji-bar.open { display: flex; }
        body.ui-modern .emoji-btn {
            background: none; border: 0; font-size: 20px; cursor: pointer;
            padding: 4px 6px; border-radius: 8px;
            transition: background .15s ease, transform .15s ease; line-height: 1;
        }
        body.ui-modern .emoji-btn:hover { background: rgba(42,161,152,0.15); transform: scale(1.15); }

        /* Уведомления */
        .unread-badge {
            background:#dc322f; color:#fff; border-radius:10px;
            padding:1px 7px; font-size:10px; margin-left:5px;
            display:inline-block; min-width:18px; text-align:center;
        }

        @media (prefers-reduced-motion: reduce) {
            body.ui-modern * { animation: none !important; transition: none !important; }
        }
    </style>
</head>
<body class="theme-<?php echo e($theme); ?> ui-<?php echo e($uiMode); ?>">
<div class="box">
    <?php if(!$myU): ?>
        <div class="hdr"><span>Вход и регистрация в CrossEra</span></div>
        <div class="main-panel">
            <?php if(isset($_SESSION['ce_error'])): echo "<div class='err-msg'>" . e($_SESSION['ce_error']) . "</div>"; unset($_SESSION['ce_error']); endif; ?>
            <form method="POST" style="max-width:300px; margin:20px auto;">
                ID (логин латиницей): <input name="u_id" required style="width:100%; padding:5px; margin-bottom:5px;"><br>
                Ник (отображаемое имя): <input name="dn" style="width:100%; padding:5px; margin-bottom:5px;"><br>
                Пароль: <input name="pwd" type="password" required style="width:100%; padding:5px; margin-bottom:10px;"><br>
                <input type="submit" name="login" value="Войти" class="btn" style="width:48%;">
                <input type="submit" name="register" value="Создать" class="btn" style="width:48%; background:#586e75;">
            </form>
        </div>
    <?php else: ?>
        <?php $unreadTotal = total_unread_pm($myU); ?>
        <div class="hdr">
            <a href="?view=profile&uid=<?php echo urlencode($myU); ?>" style="color:white; text-decoration:none;">
                <?php echo get_avatar_html($myU, $myN); ?> <span><?php echo e($myN); ?></span>
            </a>
            <div style="float:right;">
                <span style="font-size:9px; opacity:0.7; margin-right:8px;">UI: <?php echo e($uiMode); ?></span>
                <?php if($unreadTotal > 0): ?>
                    <a href="?view=contacts" style="color:#fff; background:#dc322f; padding:2px 8px; border-radius:10px; font-size:10px; text-decoration:none; margin-right:8px;">💬 <?php echo (int)$unreadTotal; ?></a>
                <?php endif; ?>
                <a href="?view=search" style="color:white; margin-right:10px; text-decoration:none;">Поиск</a>
                <a href="?logout=1&csrf=<?php echo e($csrf); ?>" style="color:white; font-size:10px;">[Выход]</a>
            </div>
            <div style="clear:both;"></div>
        </div>

        <div class="nav">
            <a href="?view=chat&to=all" class="<?php echo ($view=='chat'&&$to=='all')?'active':''; ?>">Общий Чат</a>
            <a href="?view=groups" class="<?php echo ($view=='groups'||strpos($to,'group_')===0||strpos($to,'gb_')===0)?'active':''; ?>">Группы/Каналы</a>
            <a href="?view=contacts" class="<?php echo ($view=='contacts')?'active':''; ?>">Контакты<?php if($unreadTotal > 0) echo ' <span class="unread-badge">' . (int)$unreadTotal . '</span>'; ?></a>
            <a href="?view=chat&to=saved" class="<?php echo ($view=='chat'&&$to=='saved_'.$myU)?'active':''; ?>">Избранное</a>
            <a href="?view=mods_page" class="<?php echo ($view=='mods_page'||$view=='edit_mod'||$view=='run_mod'||$view=='dev_info')?'active':''; ?>">Модули</a>
            <a href="?view=digest" class="<?php echo ($view=='digest')?'active':''; ?>">Дайджест</a>
            <a href="?view=settings" class="<?php echo ($view=='settings')?'active':''; ?>">Настройки</a>
            <a href="?view=logins" class="<?php echo ($view=='logins')?'active':''; ?>">Входы</a>
            <a href="?view=profile&uid=<?php echo urlencode($myU); ?>" class="<?php echo ($view=='profile'&&($_GET['uid']??'')==$myU)?'active':''; ?>">Инфо</a>
            <a href="?view=eula" class="<?php echo ($view=='eula')?'active':''; ?>">EULA</a>
            <a href="?view=license" class="<?php echo ($view=='license')?'active':''; ?>">Лицензия</a>
        </div>

        <div class="content">
            <?php if($view == 'digest'): ?>
                <div class="main-panel">
                    <h3>Текстовый дайджест обновлений</h3><br>
                    <?php
                    if(file_exists($reqF)):
                        foreach(file($reqF) as $l):
                            if(strpos($l, '<?php') !== false || !trim($l)) continue;
                            $d = explode('|', trim($l));
                            if(($d[1]??'') == $myU):
                                $from_id = e($d[0]);
                                $from_name = e($d[2] ?? $d[0]);
                    ?>
                                <div class="mod-card" style="background:#b58900; color:white; border:none;">
                                    Пользователь <b><?php echo $from_name; ?></b> (@<?php echo $from_id; ?>) хочет добавить вас в контакты.
                                    <div style="margin-top:5px;">
                                        <a href="?req_action=accept&from_uid=<?php echo urlencode($from_id); ?>&csrf=<?php echo e($csrf); ?>" class="btn" style="background:#2aa198;">Принять</a>
                                        <a href="?req_action=reject&from_uid=<?php echo urlencode($from_id); ?>&csrf=<?php echo e($csrf); ?>" class="btn" style="background:#dc322f;">Отклонить</a>
                                    </div>
                                </div>
                    <?php endif; endforeach; endif; ?>
                    <div class="mod-card">
                        <b>Общий чат:</b> <?php echo has_new_messages($myU, 'all', $rDir.'global.db.php') ? "<span style='color:red;'>Есть новые сообщения!</span>" : "Нет обновлений"; ?>
                    </div>
                </div>

            <?php elseif($view == 'choose_reac'): ?>
                <div class="main-panel">
                    <h3>Выберите реакцию на сообщение</h3>
                    <p style="opacity:0.6; margin-bottom:10px;">Кликните эмодзи:</p>
                    <div class="mod-card" style="text-align:center; padding:25px 10px;">
                        <?php
                        $mid = preg_replace('/[^a-z0-9]/', '', $_GET['mid'] ?? '');
                        $emojis = ['fire.gif'=>'Огонь','smile.gif'=>'Улыбка','good.gif'=>'Класс','heart.gif'=>'Сердце'];
                        foreach($emojis as $img => $title) {
                            echo "<a href='?add_reac_id=$mid&type=" . urlencode($img) . "&to=" . urlencode($to) . "&csrf=" . e($csrf) . "' style='margin:0 12px; display:inline-block; text-decoration:none;'>";
                            echo "<img src='smiles/" . e($img) . "' width='24' height='24' style='vertical-align:middle; border:none;'><br>";
                            echo "<span style='font-size:10px; color:#2aa198; display:block; margin-top:4px;'>" . e($title) . "</span></a>";
                        }
                        ?>
                    </div>
                    <br>
                    <a href="?view=chat&to=<?php echo urlencode($to); ?>#msg_<?php echo e($mid); ?>" class="btn" style="background:#586e75;">&lt;&lt; Назад</a>
                </div>

            <?php elseif($view == 'mods_page'): ?>
                <div class="main-panel">
                    <div style="margin-bottom:10px;">
                        <h3 style="display:inline-block;">Репозиторий модулей</h3>
                        <a href="?view=dev_info" class="btn" style="background:#586e75; font-size:10px; float:right;">Для разработчиков</a>
                        <div style="clear:both;"></div>
                    </div>
                    <?php
                    $modFiles = glob($modDir . "*.php");
                    if(!empty($modFiles)):
                        foreach($modFiles as $mf):
                            $modName = basename($mf, ".php");
                    ?>
                            <div class="mod-card">
                                <b>Модуль: <?php echo e($modName); ?></b><br>
                                <small style="opacity:0.6;"><?php echo e($mf); ?></small>
                                <div style="margin-top:8px;">
                                    <a href="?view=run_mod&name=<?php echo urlencode($modName); ?>" class="btn">Запустить</a>
                                    <a href="?view=edit_mod&name=<?php echo urlencode($modName); ?>" class="btn" style="background:#b58900;">Исходный код</a>
                                </div>
                            </div>
                    <?php endforeach; else: echo "<div class='mod-card' style='text-align:center; padding:20px; color:#777;'>Папка /mods/ пуста.</div>"; endif; ?>
                </div>

            <?php elseif($view == 'dev_info'): ?>
                <div class="main-panel">
                    <h3>Документация разработчика модулей</h3><br>
                    <div class="mod-card" style="font-size:11px;">
                        <p>Для публикации отправьте скрипт на <b>mindindevin@gmail.com</b></p>
                    </div>
                    <br>
                    <textarea style="width:100%; height:320px; font-family:monospace; font-size:10px; padding:8px;" readonly>Разработка расширений для CrossEra Engine.

1. Модули размещаются в /mods/
2. Ядро подключает модуль при ?view=run_mod&name=имя_файла
3. Правила:
   - без тегов html/head/body
   - сохранять GET-параметры ядра
   - Post-Redirect-Get после POST
   - изоляция CSS в уникальном контейнере
4. Ограничения: JS только для декоративных улучшений</textarea>
                    <br><br>
                    <a href="?view=mods_page" class="btn" style="background:#586e75;">Назад</a>
                </div>

            <?php elseif($view == 'eula'): ?>
                <div class="main-panel">
                    <h3>Лицензионное соглашение (EULA)</h3><br>
                    <div class="mod-card" style="line-height:1.6; font-size:11px; text-align:justify;">
                        <b>1. Общие положения</b><br>Используя CrossEra, вы соглашаетесь с условиями. Если не согласны — прекратите использование.<br><br>
                        <b>2. Контент</b><br>Пользователь несёт ответственность за передаваемую информацию. Запрещён спам, вредоносное ПО, оскорбления, нарушение закона.<br><br>
                        <b>3. Отказ от гарантий</b><br>ПО предоставляется "как есть". Разработчик не несёт ответственности за сбои, потерю данных и доступность.<br><br>
                        <b>4. Безопасность</b><br>Сообщения шифруются AES-128-CTR. Пароли хешируются (password_hash).<br><br>
                        <small style="opacity:0.6;">Редакция: <?php echo date('Y-m-d'); ?>.</small>
                    </div>
                </div>

            <?php elseif($view == 'license'): ?>
                <div class="main-panel">
                    <h3>Лицензия исходного кода (MIT)</h3><br>
                    <textarea style="width:100%; height:280px; font-family:monospace; font-size:10px; padding:8px;" readonly>Copyright (c) <?php echo date('Y'); ?> Impisre Software

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.</textarea>
                </div>

            <?php elseif($view == 'run_mod'): ?>
                <div class="main-panel">
                    <?php
                    $mName = preg_replace('/[^a-z0-9_\-]/i', '', $_GET['name'] ?? '');
                    $mPath = realpath($modDir . $mName . ".php");
                    $modRealDir = realpath($modDir);
                    if($mName !== '' && $mPath && $modRealDir && strpos($mPath, $modRealDir) === 0 && file_exists($mPath)) {
                        include($mPath);
                    } else echo "<div class='err-msg'>Модуль не найден!</div>";
                    ?>
                </div>

            <?php elseif($view == 'edit_mod'): ?>
                <div class="main-panel">
                    <?php
                    $mName = preg_replace('/[^a-z0-9_\-]/i', '', $_GET['name'] ?? '');
                    $mPath = realpath($modDir . $mName . ".php");
                    $modRealDir = realpath($modDir);
                    if($mName !== '' && $mPath && $modRealDir && strpos($mPath, $modRealDir) === 0 && file_exists($mPath)): ?>
                        <h3>Код модуля: <?php echo e($mName); ?>.php</h3><br>
                        <textarea style="width:100%; height:280px; font-family:monospace; font-size:11px; padding:5px;" readonly><?php echo e(file_get_contents($mPath)); ?></textarea><br><br>
                        <a href="?view=mods_page" class="btn" style="background:#586e75;">Назад</a>
                    <?php else: echo "Модуль не найден."; endif; ?>
                </div>

            <?php elseif($view == 'search'): ?>
                <div class="main-panel">
                    <h3>Поиск по платформе</h3><br>
                    <?php $searchIn = preg_replace('/[^a-z0-9_]/', '', $_GET['in'] ?? ''); ?>
                    <form method="GET" style="margin-bottom:15px;">
                        <input type="hidden" name="view" value="search">
                        <input type="hidden" name="in" value="<?php echo e($searchIn); ?>">
                        <input type="text" name="q" value="<?php echo e($_GET['q']??''); ?>" placeholder="Что искать?" style="padding:5px; width:70%;">
                        <input type="submit" value="Найти" class="btn">
                    </form>
                    <?php if($searchIn): ?>
                        <p style="font-size:11px; opacity:0.7;">Поиск в комнате: <b><?php echo e($searchIn); ?></b> — <a href="?view=search&q=<?php echo urlencode($_GET['q']??''); ?>">искать везде</a></p><br>
                    <?php endif; ?>
                    <?php
                    $q = strtolower(htmlspecialchars($_GET['q']??'', ENT_QUOTES, 'UTF-8'));
                    if($q):
                        if ($searchIn) {
                            $sf = resolve_chat_file($searchIn, $myU);
                            if ($sf && file_exists($sf)) {
                                echo "<h4>Результаты в комнате:</h4><br>";
                                foreach(file($sf) as $l) {
                                    if(strpos($l, '<?php') !== false || !trim($l)) continue;
                                    $d = explode('|', trim($l));
                                    $msg = v_crypt($d[1]??'', $crypto_key, 'dec');
                                    if(strpos(strtolower($msg), $q)!==false) {
                                        echo "<div class='mod-card' style='font-size:11px;'><b>" . e($d[0]) . " <span style='opacity:0.5'>" . e($d[2]??'') . "</span>:</b> " . parse_msg($msg) . "</div>";
                                    }
                                }
                            } else echo "<div class='err-msg'>Комната не найдена.</div>";
                        } else {
                            echo "<h4>Люди:</h4><br>";
                            if(file_exists($passF)) {
                                foreach(file($passF) as $l) {
                                    if(strpos($l, '<?php')!==false) continue;
                                    $d = explode('|', trim($l));
                                    if(strpos(strtolower($d[0]??''), $q)!==false || strpos(strtolower($d[2]??''), $q)!==false) {
                                        echo "• <a href='?view=profile&uid=" . urlencode($d[0]) . "'>" . e($d[2]) . " (@" . e($d[0]) . ")</a><br>";
                                    }
                                }
                            }
                            echo "<br><b>Группы и Каналы:</b><br>";
                            if(file_exists($groupsF)) {
                                foreach(file($groupsF) as $l) {
                                    if(strpos($l, '<?php')!==false) continue;
                                    $d = explode('|', trim($l));
                                    if(strpos(strtolower($d[1]??''), $q)!==false) {
                                        $target = "group_".preg_replace('/[^a-z0-9_]/','',$d[0]);
                                        echo "• <a href='?view=chat&to=" . urlencode($target) . "'>" . e($d[1]) . " (" . (($d[2] ?? '') === 'channel' ? 'Канал' : 'Группа') . ")</a><br>";
                                    }
                                }
                            }
                            echo "<br><b>Общий чат:</b><br>";
                            if(file_exists($rDir."global.db.php")) {
                                foreach(file($rDir."global.db.php") as $l) {
                                    if(strpos($l, '<?php') !== false) continue;
                                    $d = explode('|', trim($l));
                                    $msg = v_crypt($d[1]??'', $crypto_key, 'dec');
                                    if(strpos(strtolower($msg), $q)!==false) {
                                        echo "<div class='mod-card' style='font-size:11px;'><b>" . e($d[0]) . ":</b> " . parse_msg($msg) . "</div>";
                                    }
                                }
                            }
                        }
                    endif;
                    ?>
                </div>

            <?php elseif($view == 'settings'): ?>
                <div class="main-panel">
                    <h3>Настройки</h3><br>
                    <?php if(!empty($_SESSION['ce_error'])): ?>
                        <div class="err-msg"><?php echo e($_SESSION['ce_error']); unset($_SESSION['ce_error']); ?></div>
                    <?php endif; ?>
                    <?php if(!empty($_SESSION['ce_msg'])): ?>
                        <div class="mod-card" style="background:#2aa198; color:white; border:none; text-align:center;">
                            <?php echo e($_SESSION['ce_msg']); unset($_SESSION['ce_msg']); ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" class="mod-card">
                        <?php echo '<input type="hidden" name="csrf" value="' . e($csrf) . '">'; ?>
                        <b>1. Ник</b><br>
                        <input type="text" name="new_nick" value="<?php echo e($myN); ?>" maxlength="32" style="width:100%; padding:5px; margin:5px 0;"><br><br>

                        <b>2. Смена пароля</b><br>
                        <input type="password" name="old_pwd" placeholder="Текущий пароль" style="width:100%; padding:5px; margin:5px 0;"><br>
                        <input type="password" name="new_pwd" placeholder="Новый пароль" style="width:100%; padding:5px; margin:5px 0;"><br>
                        <input type="password" name="new_pwd2" placeholder="Повтор" style="width:100%; padding:5px; margin:5px 0;"><br><br>

                        <b>3. Тема</b><br>
                        <label><input type="radio" name="theme" value="light" <?php if($theme==='light') echo 'checked'; ?>> Светлая</label>
                        <label style="margin-left:10px;"><input type="radio" name="theme" value="dark" <?php if($theme==='dark') echo 'checked'; ?>> Тёмная</label><br><br>

                        <b>4. Режим интерфейса</b><br>
                        <label><input type="radio" name="ui_mode" value="auto"    <?php if($themeMode==='auto')    echo 'checked'; ?>> Авто</label>
                        <label style="margin-left:10px;"><input type="radio" name="ui_mode" value="modern"  <?php if($themeMode==='modern')  echo 'checked'; ?>> Modern</label>
                        <label style="margin-left:10px;"><input type="radio" name="ui_mode" value="classic" <?php if($themeMode==='classic') echo 'checked'; ?>> Classic</label><br>
                        <small style="opacity:0.6;">Определён: <b><?php echo e($uiMode); ?></b></small><br><br>

                        <input type="submit" name="save_settings" value="Сохранить" class="btn">
                    </form>
                </div>

            <?php elseif($view == 'logins'): ?>
                <div class="main-panel">
                    <h3>Журнал входов</h3>
                    <p style="font-size:10px; opacity:0.7; margin-bottom:10px;">Последние 30 записей.</p>
                    <?php
                    $log = get_login_log($myU, 30);
                    if(empty($log)): ?>
                        <div class="mod-card" style="text-align:center; color:#777; padding:20px;">Пока нет записей.</div>
                    <?php else: foreach($log as $entry):
                        $statusMap = [
                            'ok'         => ['Успешный вход','#2aa198'],
                            'fail'       => ['Неудачная попытка','#dc322f'],
                            'register'   => ['Регистрация','#b58900'],
                            'pwd_change' => ['Смена пароля','#268bd2'],
                        ];
                        $st = $statusMap[$entry['status']] ?? [$entry['status'],'#666'];
                        $dt = date('d.m.Y H:i', $entry['time']);
                        $deviceIcon = '💻';
                        if ($entry['device'] === 'Телефон') $deviceIcon = '📱';
                        if ($entry['device'] === 'Планшет') $deviceIcon = '📲';
                        if ($entry['device'] === 'ТВ')      $deviceIcon = '📺';
                    ?>
                        <div class="mod-card" style="border-left:4px solid <?php echo $st[1]; ?>;">
                            <div style="display:flex; justify-content:space-between;">
                                <b><?php echo $deviceIcon . ' ' . e($entry['device']); ?></b>
                                <span style="font-size:10px; color:#777;"><?php echo e($dt); ?></span>
                            </div>
                            <div style="font-size:11px; margin-top:5px;">
                                <b>ОС:</b> <?php echo e($entry['os']); ?><br>
                                <b>Браузер:</b> <?php echo e($entry['browser']); ?>
                            </div>
                            <div style="font-size:10px; margin-top:6px; color:<?php echo $st[1]; ?>; font-weight:bold;">
                                <?php echo e($st[0]); ?>
                            </div>
                        </div>
                    <?php endforeach; endif; ?>
                    <br>
                    <a href="?view=settings" class="btn" style="background:#586e75;">&lt;&lt; Настройки</a>
                </div>

            <?php elseif($view == 'profile'): ?>
                <?php
                $uid = preg_replace('/[^a-z0-9_]/', '', $_GET['uid'] ?? $myU);
                if ($uid === '') $uid = $myU;
                $cf = $viewsDir . md5($uid) . '.txt';
                $views = file_exists($cf) ? (int)file_get_contents($cf) : 0;
                if($uid != $myU) { $views++; file_put_contents($cf, $views); }

                $name = $uid; $about = "О себе ничего не указано.";
                if(file_exists($passF)) {
                    foreach(file($passF) as $l) {
                        $d = explode('|', trim($l));
                        if(($d[0]??'') == $uid) { $name = $d[2]??$uid; break; }
                    }
                }
                if(file_exists($avatarDir . md5($uid) . '.txt')) $about = file_get_contents($avatarDir . md5($uid) . '.txt');
                $profileLast = get_last_seen($uid);
                $profileOnline = is_user_online($uid);
                ?>
                <div class="main-panel" style="text-align:center;">
                    <?php echo get_avatar_html($uid, $name); ?><br><br>
                    <h3><?php echo e($name); ?> (@<?php echo e($uid); ?>)</h3>
                    <p style="font-size:11px; margin-top:6px;">
                        <?php if($profileOnline): ?>
                            <span style="color:#2aa198;">● в сети</span>
                        <?php else: ?>
                            <span style="opacity:0.6;">○ <?php echo e(human_last_seen($profileLast)); ?></span>
                        <?php endif; ?>
                    </p>
                    <p style="font-size:10px; color:#777; margin-top:4px;">Просмотров: <b><?php echo (int)$views; ?></b></p>
                    <hr style="margin:15px 0; opacity:0.2;">
                    <div class="mod-card" style="text-align:left; min-height:60px;">
                        <b>Инфо:</b><br><?php echo nl2br(e($about)); ?>
                    </div>
                    <?php if($uid == $myU): ?>
                        <form method="POST" enctype="multipart/form-data" style="text-align:left;" class="mod-card">
                            <?php echo '<input type="hidden" name="csrf" value="' . e($csrf) . '">'; ?>
                            <b>Визитка:</b><br>
                            <label style="font-size:10px;">Аватар:</label> <input type="file" name="ava_file"><br><br>
                            <textarea name="about" style="width:100%; height:50px;"><?php echo e($about); ?></textarea><br>
                            <input type="submit" name="up_profile" value="Сохранить" class="btn">
                            <a href="?toggle_theme=1&csrf=<?php echo e($csrf); ?>" class="btn" style="background:#586e75; float:right;">Тема</a>
                        </form>
                    <?php else: ?>
                        <a href="?add_c=<?php echo urlencode($uid); ?>&csrf=<?php echo e($csrf); ?>" class="btn">+ В контакты</a>
                        <a href="?view=chat&to=<?php echo urlencode(($myU < $uid) ? "pm_{$myU}_{$uid}" : "pm_{$uid}_{$myU}"); ?>" class="btn" style="background:#a01ae8;">Написать</a>
                    <?php endif; ?>
                </div>

            <?php elseif($view == 'edit'): ?>
                <div class="main-panel">
                    <h3>Редактирование</h3><br>
                    <?php
                    $mid = preg_replace('/[^a-z0-9]/', '', $_GET['mid'] ?? '');
                    $old_text = '';
                    if($curF && file_exists($curF)) {
                        foreach(file($curF) as $l) {
                            if(md5(trim($l)) == $mid) {
                                $d = explode('|', trim($l));
                                if(($d[3]??'') == $myU) $old_text = v_crypt($d[1], $crypto_key, 'dec');
                                break;
                            }
                        }
                    }
                    if($old_text): ?>
                        <form method="POST">
                            <?php echo '<input type="hidden" name="csrf" value="' . e($csrf) . '">'; ?>
                            <input type="hidden" name="mid" value="<?php echo e($mid); ?>">
                            <textarea name="new_text" style="width:100%; height:60px; padding:5px;"><?php echo e($old_text); ?></textarea><br><br>
                            <input type="submit" name="edit_msg" value="Применить" class="btn">
                            <a href="?view=chat&to=<?php echo urlencode($to); ?>" class="btn" style="background:#586e75;">Отмена</a>
                        </form>
                    <?php else: echo "Не найдено."; endif; ?>
                </div>

            <?php elseif($view == 'groups'): ?>
                <div class="main-panel">
                    <h3>Каналы и Группы</h3><br>

                    <form method="GET" style="display:flex; gap:4px; margin-bottom:12px;">
                        <input type="hidden" name="view" value="groups">
                        <input type="text" name="gq" value="<?php echo e($_GET['gq'] ?? ''); ?>" placeholder="Поиск группы по названию..." style="flex:1; padding:6px;">
                        <input type="submit" value="Найти" class="btn">
                    </form>

                    <?php $gq = trim(strtolower($_GET['gq'] ?? '')); ?>

                    <?php if($gq === ''): ?>
                        <form method="POST" style="background:rgba(0,0,0,0.05); padding:10px; border-radius:5px; margin-bottom:15px;">
                            <?php echo '<input type="hidden" name="csrf" value="' . e($csrf) . '">'; ?>
                            <input name="r_name" required placeholder="Название" style="padding:4px;">
                            <select name="r_type" style="padding:3px;">
                                <option value="group">Группа</option>
                                <option value="channel">Канал</option>
                            </select>
                            <input type="submit" name="create_room" value="Создать" class="btn">
                        </form>

                        <h4>Мои группы и подписки:</h4><br>
                        <?php
                        $mine = my_groups($myU);
                        if(empty($mine)) {
                            echo "<div class='mod-card' style='text-align:center; color:#777;'>У вас пока нет групп. Воспользуйтесь поиском.</div>";
                        }
                        foreach($mine as $g):
                            $g_target = "group_" . $g['id'];
                            $unreadG = count_unread($myU, $g_target, $rDir . $g_target . ".db.php");
                        ?>
                            <div class="mod-card">
                                <b>[<?php echo $g['type']==='channel' ? 'Канал' : 'Группа'; ?>] <?php echo e($g['name']); ?></b>
                                <small style="opacity:0.6;"> • <?php echo (int)$g['subs']; ?> подписч.<?php if($g['owner'] === $myU) echo ' • вы владелец'; ?></small>
                                <?php if($unreadG > 0): ?><span class="unread-badge"><?php echo (int)$unreadG; ?></span><?php endif; ?>
                                <a href="?view=chat&to=<?php echo urlencode($g_target); ?>" class="btn" style="float:right;">Войти</a>
                            </div>
                        <?php endforeach; ?>

                    <?php else: ?>
                        <h4>Результаты «<?php echo e($_GET['gq']); ?>»:</h4><br>
                        <?php
                        $found = false;
                        if(file_exists($groupsF)) {
                            foreach(file($groupsF) as $l) {
                                if(strpos($l, '<?php') !== false || !trim($l)) continue;
                                $g = explode('|', trim($l));
                                if(count($g) < 4) continue;
                                if(strpos(strtolower($g[1]), $gq) === false) continue;
                                $found = true;
                                $g_target = "group_" . $g[0];
                                $already = ($g[3] === $myU) || is_subscribed($myU, $g[0]);
                        ?>
                                <div class="mod-card">
                                    <b>[<?php echo ($g[2]==='channel'?'Канал':'Группа'); ?>] <?php echo e($g[1]); ?></b>
                                    <small style="opacity:0.6;"> • <?php echo (int)get_subs_count($g[0]); ?> подписч.</small>
                                    <div style="margin-top:6px;">
                                        <?php if($already): ?>
                                            <a href="?view=chat&to=<?php echo urlencode($g_target); ?>" class="btn">Открыть</a>
                                        <?php else: ?>
                                            <a href="?sub=<?php echo urlencode($g[0]); ?>&do=on&csrf=<?php echo e($csrf); ?>" class="btn">Подписаться</a>
                                        <?php endif; ?>
                                    </div>
                                </div>
                        <?php } } if(!$found) echo "<div class='mod-card' style='text-align:center; color:#777;'>Ничего не найдено.</div>"; ?>
                    <?php endif; ?>
                </div>

            <?php elseif($view == 'contacts'): ?>
                <div class="main-panel">
                    <h3>Мои контакты</h3><br>
                    <?php $cf = $rDir . "contacts_" . $myU . ".db.php"; if(file_exists($cf)):
                        foreach(file($cf) as $l): if(strpos($l,'<?php')!==false || !trim($l))continue; $c=explode('|',trim($l));
                        $c0_safe = preg_replace('/[^a-z0-9_]/', '', $c[0]);
                        $pm = ($myU < $c0_safe) ? "pm_{$myU}_{$c0_safe}" : "pm_{$c0_safe}_{$myU}";
                        $pmF = $rDir . $pm . ".db.php";
                        $unreadN = count_unread($myU, $pm, $pmF);
                        $isOn = is_user_online($c0_safe);
                    ?>
                        <div class="mod-card">
                            <?php echo get_avatar_html($c0_safe, $c[1]); ?>
                            <b><?php echo e($c[1]); ?></b>
                            <?php if($isOn): ?><span style="color:#2aa198; font-size:9px;">● online</span><?php endif; ?>
                            <?php if($unreadN > 0): ?><span class="unread-badge"><?php echo (int)$unreadN; ?></span><?php endif; ?>
                            <a href="?view=chat&to=<?php echo urlencode($pm); ?>" class="btn" style="float:right;">Диалог</a>
                        </div>
                    <?php endforeach; else: echo "Список пуст"; endif; ?>
                </div>

            <?php elseif($view == 'chat'): ?>
                <?php
                $isChannel = false; $channelOwner = '';
                if(strpos($to, 'group_') === 0) {
                    $r_id = str_replace('group_', '', $to);
                    if(file_exists($groupsF)) {
                        foreach(file($groupsF) as $gl) {
                            $gd = explode('|', trim($gl));
                            if(($gd[0] ?? '') == $r_id && ($gd[2]??'') == 'channel') { $isChannel = true; $channelOwner = $gd[3]??''; break; }
                        }
                    }
                }
                $isGuestbook = (strpos($to, 'gb_') === 0);
                $isPM = (strpos($to, 'pm_') === 0);
                $pmPartner = '';
                if ($isPM) {
                    $p = explode('_', substr($to, 3));
                    foreach ($p as $x) if ($x !== $myU) { $pmPartner = $x; break; }
                }
                ?>
                <div style="background:rgba(0,0,0,0.02); padding:5px 10px; font-size:10px; margin-bottom:5px; display:flex; justify-content:space-between; flex-wrap:wrap;">
                    <span>Комната: <b><?php echo e($to); ?></b> <?php if($isChannel) echo "(Канал)"; if($isGuestbook) echo "(Гостевая)"; ?></span>
                    <span>
                        <a href="?view=search&in=<?php echo urlencode($to); ?>" style="color:#b58900; text-decoration:none;">🔍 поиск</a>
                        &nbsp;|&nbsp;
                        <a href="?export=txt&to=<?php echo urlencode($to); ?>&csrf=<?php echo e($csrf); ?>" style="color:#2aa198; text-decoration:none;">.TXT</a>
                        <a href="?export=json&to=<?php echo urlencode($to); ?>&csrf=<?php echo e($csrf); ?>" style="color:#2aa198; text-decoration:none; margin-left:4px;">.JSON</a>
                        <a href="?export=html&to=<?php echo urlencode($to); ?>&csrf=<?php echo e($csrf); ?>" style="color:#2aa198; text-decoration:none; margin-left:4px;">.HTML</a>
                    </span>
                </div>

                <?php if($isPM && $pmPartner):
                    $partnerName = $pmPartner;
                    foreach(file($passF) as $pl) {
                        $pd = explode('|', trim($pl));
                        if(($pd[0]??'') === $pmPartner) { $partnerName = $pd[2]??$pmPartner; break; }
                    }
                    $online = is_user_online($pmPartner);
                    $last   = get_last_seen($pmPartner);
                ?>
                <div style="background:rgba(42,161,152,0.1); padding:6px 10px; border-radius:5px; margin-bottom:8px; font-size:11px;">
                    <?php echo get_avatar_html($pmPartner, $partnerName); ?>
                    <b><?php echo e($partnerName); ?></b>
                    &nbsp;•&nbsp;
                    <?php if($online): ?>
                        <span style="color:#2aa198; font-weight:600;">● в сети</span>
                    <?php else: ?>
                        <span style="color:#888;">○ <?php echo e(human_last_seen($last)); ?></span>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <?php if($isChannel && $channelOwner !== $myU):
                    $isSub = is_subscribed($myU, str_replace('group_','',$to));
                ?>
                <div style="margin-bottom:8px;">
                    <?php if($isSub): ?>
                        <a href="?sub=<?php echo urlencode(str_replace('group_','',$to)); ?>&do=off&csrf=<?php echo e($csrf); ?>" class="btn" style="background:#586e75;">Отписаться</a>
                    <?php else: ?>
                        <a href="?sub=<?php echo urlencode(str_replace('group_','',$to)); ?>&do=on&csrf=<?php echo e($csrf); ?>" class="btn">Подписаться</a>
                    <?php endif; ?>
                    <span style="font-size:11px; opacity:0.7; margin-left:8px;">
                        Подписчиков: <b><?php echo (int)get_subs_count(str_replace('group_','',$to)); ?></b>
                    </span>
                </div>
                <?php endif; ?>

                <div id="chat">
                    <?php
                    if($curF && file_exists($curF)):
                        $lines = file($curF);
                        foreach($lines as $idx => $l):
                            if(strpos($l, '<?php') !== false || !trim($l)) continue;
                            $d = explode('|', trim($l)); if(count($d) < 3) continue;
                            $uid = preg_replace('/[^a-z0-9_]/', '', $d[3] ?? '');
                            $msgID = md5(trim($l));
                            $plainMsg = v_crypt($d[1], $crypto_key, 'dec');
                            $isEdited = ($d[4] ?? 0) == 1;

                            $isMine = ($uid == $myU);
                            $readStatus = '';
                            if ($isMine && $isPM && $pmPartner) {
                                $readTime = get_last_view_time($pmPartner, $to);
                                $readStatus = $readTime > 0
                                    ? '<span style="color:#2aa198;" title="Прочитано">✓✓</span>'
                                    : '<span style="opacity:0.4;" title="Отправлено">✓</span>';
                            }
                    ?>
                            <div class="m" id="msg_<?php echo e($msgID); ?>">
                                <?php echo get_avatar_html($uid, $d[0]); ?>
                                <a href="?view=profile&uid=<?php echo urlencode($uid); ?>" style="text-decoration:none; color:inherit;"><b><?php echo e($d[0]); ?></b></a>

                                <span style="float:right; opacity:0.5; font-size:10px;">
                                    <?php echo e($d[2]); ?> <?php echo $readStatus; ?> <?php if($isEdited) echo "<i>(ред.)</i>"; ?>
                                    <?php if($uid == $myU && $plainMsg !== "[Сообщение удалено]"): ?>
                                        <a href="?view=edit&mid=<?php echo e($msgID); ?>&to=<?php echo urlencode($to); ?>" style="color:#b58900; text-decoration:none; margin-left:5px;">[ред]</a>
                                    <?php endif; ?>
                                    <?php if(($uid == $myU || $myU == $adminID) && $plainMsg !== "[Сообщение удалено]"): ?>
                                        <a href="?del_msg=<?php echo e($msgID); ?>&to=<?php echo urlencode($to); ?>&csrf=<?php echo e($csrf); ?>" style="color:#dc322f; text-decoration:none; margin-left:5px;">[x]</a>
                                    <?php endif; ?>
                                </span><br>

                                <div style="margin-left:29px; margin-top:3px; font-size:13px;"><?php echo parse_msg($plainMsg, $msgID); ?></div>

                                <?php if($isChannel && !$isGuestbook): ?>
                                    <div style="margin-left:29px; margin-top:4px;">
                                        <a href="?view=chat&to=gb_<?php echo e($msgID); ?>" style="font-size:10px; color:#2aa198; text-decoration:none;">Гостевая (Отзывы)</a>
                                    </div>
                                <?php endif; ?>

                                <div class="reac-bar">
                                    <?php
                                    $rf = $reacDir . $msgID . ".db.php";
                                    if(file_exists($rf)) {
                                        $rcs = file($rf); $counts = [];
                                        foreach($rcs as $rl) {
                                            if(strpos($rl, '<?php') !== false) continue;
                                            $d_r = explode('|', trim($rl));
                                            if(isset($d_r[2])) {
                                                $safe_reac = preg_replace('/[^a-z0-9\.]/', '', $d_r[2]);
                                                $counts[$safe_reac] = ($counts[$safe_reac] ?? 0) + 1;
                                            }
                                        }
                                        foreach($counts as $img => $count) {
                                            echo "<span class='reac-btn'><img src='smiles/" . e($img) . "' width='12'> " . (int)$count . "</span>";
                                        }
                                    }
                                    ?>
                                    <a href="?view=choose_reac&mid=<?php echo e($msgID); ?>&to=<?php echo urlencode($to); ?>"
                                       class="reac-label reac-trigger"
                                       data-mid="<?php echo e($msgID); ?>">[+]</a>

                                    <?php if($uiMode === 'modern'): ?>
                                        <div class="reac-popup" id="rp_<?php echo e($msgID); ?>" hidden>
                                            <div class="reac-popup-inner">
                                                <?php
                                                $popEmojis = ['fire.gif'=>'🔥','smile.gif'=>'🙂','good.gif'=>'👍','heart.gif'=>'❤','hi.gif'=>'👋','sarcasm.gif'=>'😏'];
                                                foreach($popEmojis as $img => $emo):
                                                ?>
                                                    <a href="?add_reac_id=<?php echo e($msgID); ?>&type=<?php echo urlencode($img); ?>&to=<?php echo urlencode($to); ?>&csrf=<?php echo e($csrf); ?>"
                                                       class="reac-popup-btn" title="<?php echo e($emo); ?>">
                                                        <img src="smiles/<?php echo e($img); ?>" width="20" height="20" alt="<?php echo e($emo); ?>">
                                                    </a>
                                                <?php endforeach; ?>
                                            </div>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                    <?php endforeach; endif; ?>
                </div>

                <?php if(!$isChannel || $channelOwner == $myU || $isGuestbook): ?>
                    <form method="POST" enctype="multipart/form-data" class="chat-form-fixed">
                        <?php echo '<input type="hidden" name="csrf" value="' . e($csrf) . '">'; ?>

                        <?php if($uiMode === 'modern'): ?>
<div class="emoji-bar" id="emojiBar">
    <?php
    // Те же смайлы, что и в меню выбора реакций.
    // code — текстовый код для вставки в сообщение,
    // img  — картинка из папки smiles/,
    // title — подсказка.
    $pickerSmiles = [
        ':fire:'    => ['img' => 'fire.gif',    'title' => 'Огонь'],
        ':smile:'   => ['img' => 'smile.gif',   'title' => 'Улыбка'],
        ':cool:'    => ['img' => 'good.gif',    'title' => 'Класс'],
        ':heart:'   => ['img' => 'heart.gif',   'title' => 'Сердце'],
        ':hi:'      => ['img' => 'hi.gif',      'title' => 'Привет'],
        ':sarcasm:' => ['img' => 'sarcasm.gif', 'title' => 'Сарказм'],
    ];
    foreach($pickerSmiles as $code => $s) {
        echo '<button type="button" class="emoji-btn" data-emo="' . e($code) . '" title="' . e($s['title']) . '">';
        echo '<img src="smiles/' . e($s['img']) . '" width="20" height="20" alt="' . e($s['title']) . '">';
        echo '</button>';
    }
    ?>
</div>
<?php endif; ?>

                        <div style="margin-bottom:5px;">
                            <span style="font-size:9px; opacity:0.6;">Быстро:</span>
                            <?php if($uiMode === 'modern'): ?>
                                <a href="#" id="emojiToggle" class="fast-reply" style="text-decoration:none;">smiles</a>
                            <?php endif; ?>
                            <a href="#" class="fast-reply" onclick="document.getElementsByName('msg')[0].value+='Да'; return false;">Да</a>
                            <a href="#" class="fast-reply" onclick="document.getElementsByName('msg')[0].value+='Нет'; return false;">Нет</a>
                            <a href="#" class="fast-reply" onclick="document.getElementsByName('msg')[0].value+='Ок'; return false;">Ок</a>
                            <a href="#" class="fast-reply" onclick="var t=document.getElementsByName('msg')[0]; t.value+='[poll]Вопрос?|Вариант 1|Вариант 2[/poll]'; return false;">📊 Опрос</a>
                        </div>
                        <textarea name="msg" style="width:100%; height:35px; border-radius:3px; padding:4px;" placeholder="Ваше сообщение..."></textarea>
                        <div style="margin-top:4px;">
                            <input type="file" name="f" style="font-size:10px; width:60%;">
                            <input type="submit" name="send_msg" value="&gt;&gt;" class="btn" style="padding:3px 12px; float:right;">
                        </div>
                    </form>
                <?php else: ?>
                    <div class="chat-form-fixed" style="text-align:center; font-size:11px; color:#666; padding:10px;">Это канал. Писать может только создатель.</div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

<?php if($uiMode === 'modern' && $myU): ?>
<script>
(function(){
    document.body.classList.add('js-on');

    // Реакции — попап
    var openPopup = null;
    function closePopup() {
        if (openPopup) { openPopup.hidden = true; openPopup = null; }
    }
    document.addEventListener('click', function(ev){
        var trigger = ev.target.closest('.reac-trigger');
        if (trigger) {
            ev.preventDefault();
            var mid = trigger.dataset.mid;
            var pop = document.getElementById('rp_' + mid);
            if (!pop) return;
            if (openPopup === pop) { closePopup(); return; }
            closePopup();
            pop.hidden = false;
            openPopup = pop;
            var r = pop.getBoundingClientRect();
            if (r.top < 10) window.scrollBy({ top: r.top - 20, behavior: 'smooth' });
            return;
        }
        if (ev.target.closest('.reac-popup-btn')) return;
        if (openPopup && !ev.target.closest('.reac-popup')) closePopup();
    }, true);
    document.addEventListener('keydown', function(ev){ if (ev.key === 'Escape') closePopup(); });
    window.addEventListener('scroll', closePopup, { passive: true });

    // Смайлик-пикер
    var emojiToggle = document.getElementById('emojiToggle');
    var emojiBar = document.getElementById('emojiBar');
    if (emojiToggle && emojiBar) {
        emojiToggle.addEventListener('click', function(ev){
            ev.preventDefault();
            emojiBar.classList.toggle('open');
        });
        emojiBar.addEventListener('click', function(ev){
            var btn = ev.target.closest('.emoji-btn');
            if (!btn) return;
            var ta = document.querySelector('textarea[name="msg"]');
            if (ta) { ta.value += btn.dataset.emo; ta.focus(); }
        });
    }

    // Автопрокрутка вниз
    if (document.getElementById('chat')) {
        window.scrollTo(0, document.body.scrollHeight);
    }

    // PWA service worker
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js').catch(function(){});
    }
})();
</script>
<?php endif; ?>

</body>
</html>
