import sqlite3

def main_old():
    print "Clearing database"
    db = sqlite3.connect("/tmp/appseclab.db")
    c = db.cursor()
    c.executescript("""
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `uid` varchar(64) NOT NULL DEFAULT '',
  `lastname` varchar(64) NOT NULL DEFAULT '',
  `firstname` varchar(64) NOT NULL DEFAULT '',
  `email` varchar(64) NOT NULL DEFAULT '',
  `pwd` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`uid`));

INSERT INTO `users` VALUES ('fu','Fuerst','Andreas','fu@imovies.ch','6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7');
INSERT INTO `users` VALUES ('db','Basin','David','db@imovies.ch','8d0547d4b27b689c3a3299635d859f7d50a2b805');
INSERT INTO `users` VALUES ('ms','Schlaepfer','Michael','ms@imovies.ch','4d7de8512bd584c3137bb80f453e61306b148875');
INSERT INTO `users` VALUES ('a3','Anderson','Andres Alan','and@imovies.ch','6b97f534c330b5cc78d4cc23e01e48be3377105b');

DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
  `sid` VARCHAR(40) PRIMARY KEY,
  `uid` VARCHAR(64) NOT NULL,
  `updated` DATETIME);

DROP TABLE IF EXISTS `admin_sessions`;
CREATE TABLE `admin_sessions` (
  `sid` VARCHAR(40) PRIMARY KEY,
  `uid` VARCHAR(64) NOT NULL,
  `updated` DATETIME);

DROP TABLE IF EXISTS `update_requests`;
CREATE TABLE `update_requests` (
  `id` INTEGER PRIMARY KEY,
  `uid` VARCHAR(64) NOT NULL,
  `field` VARCHAR(20) NOT NULL,
  `value_old` VARCHAR(64) NOT NULL,
  `value_new` VARCHAR(64) NOT NULL);

DROP TABLE IF EXISTS `certificates`;
CREATE TABLE `certificates` (
  `id` INTEGER PRIMARY KEY,
  `uid` VARCHAR(64) NOT NULL,
  `revoked` BOOLEAN DEFAULT FALSE,
  `title` VARCHAR(255),
  `description` TEXT,
  `certificate` TEXT);
""")
    db.commit()

def main():
    from models import Base
    from db import engine
    Base.metadata.create_all(engine)
    print "DONE"

if __name__ == "__main__":
    main()