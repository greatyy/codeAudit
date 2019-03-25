# 安装环境
windows10 + xmapp
xmapp的Apache HTTP端口设为8080

# 安装phpcms
1. 在xmapp安装文件夹htdocs文件夹内新建一个文件夹，用来放php的程序代码，我的命名习惯是cms名称+版本号，例如在这里我的
命名是phpcms_v9.6.3
2. 到[phpcms官网](http://download.phpcms.cn/v9/9.6/phpcms_v9.6.3_UTF8.zip)下载代码，解压后将install_package文件夹内的文件
复制到第一步创建的文件夹内。
3. 访问 http://127.0.0.1:8080/phpcms_v9.6.3/install安装cms

# cms基本结构
网上的一些分析文章基本上都是跳过功能点去直接分析漏洞，这对不熟悉这套cms的人或新手来说十分的不友好。在这里我简单的分析
一下这套cms的结构。
## 前台和后台
普通用户用的就是前台，url为index.php。管理员用的就是后台，url为admin.php.
一般来说前台的相同级别的漏洞危害远远比后台大。
## 模块


# RCE 1

第一个漏洞点在碎片管理
```php
public function public_view() {
		$id = isset($_GET['id']) && intval($_GET['id']) ? intval($_GET['id']) :  exit('0');
		if (!$data = $this->db->get_one(array('id'=>$id))) {
			showmessage(L('nofound'));
		}
		if ($data['type'] == 1) {
			exit('<script type="text/javascript">parent.showblock('.$id.', \''.str_replace("\r\n", '', $_POST['data']).'\')</script>');
		} elseif ($data['type'] == 2) {
			extract($data);
			unset($data);
			$title = isset($_POST['title']) ? $_POST['title'] : '';
			$url = isset($_POST['url']) ? $_POST['url'] : '';
			$thumb = isset($_POST['thumb']) ? $_POST['thumb'] : '';
			$desc = isset($_POST['desc']) ? $_POST['desc'] : '';
			$template = isset($_POST['template']) && trim($_POST['template']) ? trim($_POST['template']) : '';
			$data = array();
			foreach ($title as $key=>$v) {
				if (empty($v) || !isset($url[$key]) ||empty($url[$key])) continue;
				$data[$key] = array('title'=>$v, 'url'=>$url[$key], 'thumb'=>$thumb[$key], 'desc'=>str_replace(array(chr(13), chr(43)), array('<br />', '&nbsp;'), $desc[$key]));
			}
			$tpl = pc_base::load_sys_class('template_cache');
			$str = $tpl->template_parse(new_stripslashes($template));
			$filepath = CACHE_PATH.'caches_template'.DIRECTORY_SEPARATOR.'block'.DIRECTORY_SEPARATOR.'tmp_'.$id.'.php';
			$dir = dirname($filepath);
			if(!is_dir($dir)) {
				@mkdir($dir, 0777, true);
		    }
		    if (@file_put_contents($filepath,$str)) {
		    	 ob_start();
		   		 include $filepath;
		   		 $html = ob_get_contents();
		   		 ob_clean();
		   		 @unlink($filepath);
		    }
```

`include $filepath;`

```
$tpl = pc_base::load_sys_class('template_cache');
$str = $tpl->template_parse(new_stripslashes($template));
$filepath = CACHE_PATH.'caches_template'.DIRECTORY_SEPARATOR.'block'.DIRECTORY_SEPARATOR.'tmp_'.$id.'.php';
```

