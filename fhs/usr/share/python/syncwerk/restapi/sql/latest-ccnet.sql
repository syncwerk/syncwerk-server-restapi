-- Table `django_content_type` and `auth_permission` are required for django migrations

CREATE TABLE IF NOT EXISTS `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=209 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

ALTER TABLE LDAPUsers ADD COLUMN reference_id VARCHAR(255);
ALTER TABLE EmailUser ADD COLUMN reference_id VARCHAR(255);

ALTER TABLE `LDAPUsers` ADD UNIQUE (`reference_id`);
ALTER TABLE `EmailUser` ADD UNIQUE (`reference_id`);

CREATE TABLE IF NOT EXISTS LDAPConfig (cfg_group VARCHAR(255) NOT NULL, cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER) ENGINE=INNODB;

CREATE TABLE IF NOT EXISTS GroupStructure (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, group_id INTEGER, path VARCHAR(1024), UNIQUE INDEX(group_id))ENGINE=INNODB;

ALTER TABLE `Group` add column parent_group_id INTEGER default 0;  -- Replace `Group` if you configured table `Group` to another name.

ALTER TABLE Binding ADD id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;

ALTER TABLE LDAPConfig ADD id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;

ALTER TABLE OrgUser DROP primary key;
ALTER TABLE OrgUser ADD id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;
ALTER TABLE OrgUser ADD UNIQUE (org_id, email);

ALTER TABLE OrgGroup DROP primary key;
ALTER TABLE OrgGroup ADD id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;
ALTER TABLE OrgGroup ADD UNIQUE (org_id, group_id);

ALTER TABLE GroupUser DROP primary key;
ALTER TABLE GroupUser ADD id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;
ALTER TABLE GroupUser ADD UNIQUE (group_id, user_name);

ALTER TABLE GroupDNPair ADD id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;
