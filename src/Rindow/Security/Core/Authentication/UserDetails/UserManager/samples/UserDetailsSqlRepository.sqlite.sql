CREATE TABLE rindow_authusers   
(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password TEXT,
	disabled INTEGER,accountExpirationDate INTEGER,
	lastPasswordChangeDate INTEGER,lockExpirationDate INTEGER)
CREATE TABLE rindow_authorities (userid INTEGER,authority TEXT)
CREATE INDEX rindow_authorities_userid ON rindow_authorities (userid)
CREATE UNIQUE INDEX rindow_authorities_unique ON rindow_authorities (userid,authority)
exit
