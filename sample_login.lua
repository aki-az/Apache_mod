yaml = require("yaml")

LOGIN_REQ_URL = "/login"
LOGIN_PAGE = "/login.html"
LOGOUT_REQ_URL = "/logout"
LOGOUT_PAGE = "/logout.html"
SES_COOKIE_NAME = "sample_login"
SES_DB = "/tmp/session.yaml"

-- セッションデータをファイルからロードする
function load_db(r)

	-- セッションクッキーを登録しているyamlファイルの中身を読みだす
	local data
	local fp = io.open(SES_DB, "r")
	if fp then
		data = fp:read("*a")
		fp:close()
	else
		r:err("DB load error " .. SES_DB)
		return nil
	end

	-- 読みだした中身(yaml)をテープルに変換する
	local rv, ses_db = pcall( yaml.load, data )

	if not rv then
		r:err("yaml file format error ")
		return nil
	end

	return ses_db or {}
end

-- セッションデータをファイルにセーブする
function save_db(r, db)

	-- DB(テーブル)の中身をyamlに変換する
	local data = yaml.dump(db)

	-- 変換した中身をファイルに出力する
	local fp = io.open(SES_DB, "w")
	if fp then
		fp:write(data)
		fp:close()
	else
		r:err("DB save error " .. SES_DB)
		return nil
	end

	return true
end


-- リクエストパスとセッションクッキーに応じてURL書き換えなど処理する
-- translate_nameフックに登録される前提
function translate(r)

	-- サブリクエストは処理しない
	if not r.is_initial_req then return apache2.DECLINED end

	-- ログインリクエストはtranslate_nameフックでは処理しない
	if r.unparsed_uri == LOGIN_REQ_URL then
		return apache2.DECLINED
	end

	-- クライアントに対するヘッダ出力
	r.headers_out["Cache-Control"] = "no-cache"
	r.headers_out["Pragma"] = "no-cache"
	r.headers_out["Expires"] = "0"

	-- ログアウトリクエストを処理する
	if r.unparsed_uri == LOGOUT_REQ_URL then

		-- セッションクッキーを削除する
		r:setcookie{
			key = SES_COOKIE_NAME,
			value = "deleted",
			expires = 1,
			path = '/'
		}

		-- リクエストURLをログアウトページに書き換える
		r.uri = LOGOUT_PAGE
		return apache2.DECLINED
	end

	-- セッションクッキーがなければ、ログインページへ遷移させる
	local cookie = r:getcookie(SES_COOKIE_NAME)
	if not cookie then
		r:err("no cookie")
		r.uri = LOGIN_PAGE
		return apache2.DECLINED
	end

	-- セッションクッキーを登録しているyamlファイルの中身を読みだす
	local ses_db = load_db(r)
	if not ses_db then
		return 500
	end

	-- クッキーの値をキーにして、ユーザ名を取得する
	-- セッションDBに登録がない場合は、ログインページに遷移させる
	local user_name = ses_db[cookie]
	if not user_name then
		r:err("not registered: " .. cookie)
		r.uri = LOGIN_PAGE
		return apache2.DECLINED
	end

	r.headers_in["x-sample-login-user-name"] = user_name
	return apache2.DECLINED
end


-- セッションデータを作成して、DB登録とクッキー送出する
-- handlerフックに登録される前提
function login_handler(r)

	-- POSTを読みだして分解する
	local post = r:parsebody(1024)
	if not post then return 403 end

	if not post['name'] then return 403 end
	r:err("login_handler() start name:" .. post['name'])

	-- セッションクッキーを登録しているyamlファイルの中身を読みだす
	local ses_db = load_db(r)
	if not ses_db then
		return 500
	end

	-- セッションIDを作成する
	local msec = r:clock()	-- マイクロ秒までとれる
	math.randomseed(msec)
	local rnum = math.random(1, 999999999)
	local sesid = "A" .. r:sha1(tostring(rnum))

	ses_db[sesid] = post['name']

	-- セッションIDをDBに保存する
	if not save_db(r, ses_db) then
		return 500
	end

	-- セッションクッキーを出力する
	r:setcookie{
		key = SES_COOKIE_NAME,
		value = sesid,
		expires = os.time() + 600,  -- 有効期限は10分
		path = '/'
	}

	r:puts("registerd.")
	return apache2.OK
end
