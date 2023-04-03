SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

DROP TABLE IF EXISTS `users`, `items`, `cart`, `orders`, `ordered_items`;
USE `24emart`;

CREATE TABLE `users` (
	`id` INTEGER NOT NULL AUTO_INCREMENT, 
	`name` TEXT NOT NULL, 
	`email` VARCHAR(50) NOT NULL, 
	`phone` VARCHAR(50) NOT NULL, 
	`password` VARCHAR(250) NOT NULL, 
	`admin` BOOLEAN, 
	`email_confirmed` BOOLEAN, 
	PRIMARY KEY (`id`)
);

CREATE TABLE `items` (
	`id` INTEGER NOT NULL, 
	`name` VARCHAR(100) NOT NULL, 
	`price` FLOAT NOT NULL, 
	`category` TEXT NOT NULL, 
	`image` VARCHAR(250) NOT NULL, 
	`details` VARCHAR(250) NOT NULL, 
	`price_id` VARCHAR(250) NOT NULL, 
	PRIMARY KEY (`id`)
);

CREATE TABLE `cart` (
	`id` INTEGER NOT NULL, 
	`uid` INTEGER NOT NULL, 
	`itemid` INTEGER NOT NULL, 
	`quantity` INTEGER NOT NULL, 
	PRIMARY KEY (`id`,`quantity`), 
	FOREIGN KEY(`uid`) REFERENCES users (`id`), 
	FOREIGN KEY(`itemid`) REFERENCES items (`id`)
);

CREATE TABLE `orders` (
	`id` INTEGER NOT NULL, 
	`uid` INTEGER NOT NULL, 
	`date` DATETIME NOT NULL, 
	`status` VARCHAR(50) NOT NULL, 
	PRIMARY KEY (`id`), 
	FOREIGN KEY(`uid`) REFERENCES users (`id`)
);

CREATE TABLE `ordered_items` (
	`id` INTEGER NOT NULL, 
	`oid` INTEGER NOT NULL, 
    `cid` INTEGER NOT NULL, 
	`itemid` INTEGER NOT NULL, 
	`quantity` INTEGER NOT NULL, 
	PRIMARY KEY (`id`), 
	FOREIGN KEY(`oid`) REFERENCES orders (`id`), 
	FOREIGN KEY(`itemid`) REFERENCES items (`id`), 
	FOREIGN KEY(`cid`,`quantity`) REFERENCES cart (`id`,`quantity`)
);



INSERT INTO `items` (`id` , `name` , `price` , `category`, `image`, `details`, `price_id`) VALUES 
(1, 'iPhone12', 799, 'Apple',
'https://www.gizmochina.com/wp-content/uploads/2020/05/iphone-12-pro-max-family-hero-all-600x600.jpg', 
'6.1-inch OLED display<br>A14 Bionic chip<br>256GB storage',
'price_1Jk8KjBZlBPWG6ECQXNqcKhR'),
(2, 'iPhone 12 mini', 729, 'Apple', 
'https://fdn2.gsmarena.com/vv/pics/apple/apple-iphone-12-mini-2.jpg',  
'5.4-inch Super Retina XDR display<br>Dual 12MP camera system<br>256 GB storage',
 'price_1Jk8LrBZlBPWG6ECvsEjYsZF'),
 (3, 'iPhone 11', 699, 'Apple',
 'https://www.gizmochina.com/wp-content/uploads/2019/09/Apple-iPhone-11-1.jpg',
 'A13 Bionic chip<br>smart HDR<br>128GB storage', 'price_1Jk8MUBZlBPWG6ECueOfWc9N'),
 (4, 'Acer Nitro 5', 1300, 'laptop',
 '/static/uploads/nitro.jpg', 
 'Intel i7 10th gen<br>1920*1080 144Hz display<br>8 GB RAM<br>1 TB HDD + 256 GB SSD<br>GTX 1650 Graphics card',
 'price_1JlBEmBZlBPWG6EC1i6RYpTB'
 ),
 (5, 'Apple MacBook Pro', 1990, 'laptop',
 '/static/uploads/macbook.jpg', 
 'Intel core i5 2.4GHz<br>13.3" Retina Display<br>8 GB RAM<br>256 GB SSD<br>Touch Bar + Touch id',
 'price_1JlBIQBZlBPWG6ECsPx49z0g'
 ), 
 (6, 'Mi TV 4X', 500, 'Television',
 '/static/uploads/mi%20tv.jpg', 
 '108Cm 43" UHD 4K LED<br>Smart Android TV<br>20W speakers Dolby™+ DTS-HD®',
 'price_1JlBNABZlBPWG6ECzU6Yh1dq');