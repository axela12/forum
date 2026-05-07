-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Värd: 127.0.0.1
-- Tid vid skapande: 07 maj 2026 kl 12:15
-- Serverversion: 10.4.32-MariaDB
-- PHP-version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Databas: `forum_db`
--
CREATE DATABASE IF NOT EXISTS `forum_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `forum_db`;

-- --------------------------------------------------------

--
-- Tabellstruktur `posts`
--

CREATE TABLE `posts` (
  `id` int(10) UNSIGNED NOT NULL,
  `thread_id` int(10) UNSIGNED DEFAULT NULL,
  `user_id` int(10) UNSIGNED DEFAULT NULL,
  `content` varchar(255) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumpning av Data i tabell `posts`
--

INSERT INTO `posts` (`id`, `thread_id`, `user_id`, `content`, `created_at`) VALUES
(1, 1, 1, 'f', '2026-05-05 15:03:23'),
(2, 1, 1, 'fe', '2026-05-05 15:03:25'),
(3, 1, 1, 'f', '2026-05-05 15:03:27'),
(4, 1, 1, 'f', '2026-05-05 15:03:29'),
(5, 1, 1, 'fr', '2026-05-05 15:03:31'),
(6, 1, 1, 'f', '2026-05-05 15:03:32'),
(7, 1, 1, 'fe', '2026-05-05 15:03:34'),
(8, 1, 1, 'fef', '2026-05-05 15:03:37'),
(9, 1, 1, 'fe', '2026-05-05 15:03:38'),
(10, 1, 1, 'fe', '2026-05-05 15:03:39'),
(11, 1, 1, 'ef', '2026-05-05 15:03:49'),
(12, 1, 8, 'hj', '2026-05-06 13:18:35'),
(13, 1, 8, '78', '2026-05-06 13:18:42'),
(14, 1, 8, 'ij', '2026-05-06 13:18:49'),
(15, 1, 8, 'juj', '2026-05-06 13:18:52'),
(16, 1, 8, 'hygy', '2026-05-06 13:18:56'),
(17, 1, 8, 'jhu', '2026-05-06 13:19:13'),
(18, 1, 8, 'tjena', '2026-05-06 13:19:17');

-- --------------------------------------------------------

--
-- Tabellstruktur `threads`
--

CREATE TABLE `threads` (
  `id` int(10) UNSIGNED NOT NULL,
  `user_id` int(10) UNSIGNED DEFAULT NULL,
  `last_post_id` int(10) UNSIGNED DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `post_count` int(10) UNSIGNED DEFAULT 0,
  `last_post_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumpning av Data i tabell `threads`
--

INSERT INTO `threads` (`id`, `user_id`, `last_post_id`, `title`, `created_at`, `post_count`, `last_post_at`) VALUES
(1, 1, 18, 'fr', '2026-05-05 15:03:23', 18, '2026-05-06 13:19:17');

-- --------------------------------------------------------

--
-- Tabellstruktur `users`
--

CREATE TABLE `users` (
  `id` int(10) UNSIGNED NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `role` enum('user','admin') NOT NULL DEFAULT 'user',
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumpning av Data i tabell `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `email`, `role`, `created_at`) VALUES
(1, 'a', 'scrypt:32768:8:1$CyRiBngKJYLcFFsn$cab99d7edf4942a0454265115eff5e29feab62b4594fafaf8a3d1eecc4aac4c59ab3ccc4bbd34e57d1a92482be46ef34d25730c224bbf425c2551a5cf6a3ddd2', 'axel.krantz@skola.taby.se', 'admin', '2026-05-05 14:00:32'),
(2, '1', 'scrypt:32768:8:1$mQpr6O1FKCHUMAHH$522c1cb020f7f35a0573fb8804f27bfc1e37a32773efb58d46c43bb124dfef99df3f4efde61adb57ff4412452c77947b9da32d35624af9c6f5c7a5022449142e', 'axel@skola.taby.se', 'user', '2026-05-05 14:35:55'),
(3, '2', 'scrypt:32768:8:1$e5Dw8wt9JZvYXVCo$57692110fbd6a238f77a0d99dc3cc5fa36e9ffca3322cb280faa0a2f839964803ad69d2544022ec7b38fc8abdb5eee6b500d21f014092538639a9d66bdab69d5', '.krantz@skola.taby.se', 'user', '2026-05-05 14:36:08'),
(4, '3', 'scrypt:32768:8:1$sDEdAaNqrj428et9$a1fc46c8081da97dccc61ed2998d9924fa62977dd1e493d02d8b1b6de3f32ca3a73eb8ce50327d234366776a3f3850453e8a5a2f3039f6075668f06a944bf708', 'axel.krantz@taby.se', 'user', '2026-05-05 14:36:43'),
(5, '4', 'scrypt:32768:8:1$4WfZLBHUK0A1se9p$cd8432645934e4326bfae407c532ca7ac114945d3f83278d050688ae57f4f5822ef421b1bb861a91dedc8d93dc90b5bf07601b674a1b0021d4602d5e2079338d', 'axel.krantz@skola.se', 'user', '2026-05-05 15:05:11'),
(6, '5', 'scrypt:32768:8:1$s2Pqv3S97uobtKJ8$38e5b17e04d97d2389e5a96c1414c21fb095923bf447145339be3fc8fc76790687685d983553a212c1b52385cd6d1cf1c376a89852d783388aa4dda67d2f4c0b', 'krantz@skola.taby.se', 'user', '2026-05-05 15:05:25'),
(7, '6', 'scrypt:32768:8:1$60pJDLSHMNA8lJ0S$3f132aea8c71e153684d7877e1b9d5b62356da1f37bb53c9281280a7e2b34c2f7fff11c6f7e54f6f58be680a29a8eaae7c70fe55aef9f245d3ad012d0c59d2ff', 'axelkrantz@skola.taby.se', 'user', '2026-05-05 16:14:47'),
(8, '7', 'scrypt:32768:8:1$Ywe94WElF2MIAOTA$97e6067b7387d01dba1ae5ff5b8d9eebdabffab84a6726fc1d5a7793d1a85183b6e836dace11cf277b88cfdee0b92ac4b4832d524ae5d7196ee853d1edd102a1', 'ax@skola.taby.se', 'user', '2026-05-06 13:18:17'),
(9, '8', 'scrypt:32768:8:1$9Bf7JJPcJzefDKwS$d4cc030a519cebe8a9819af00b166c75b0f6a6506e63426fb603e173bdf4d7594c23115e200d9bbeba3518e70ecb27bedf1b2dee1b8b6a4d51573dcfdc6d1517', 'ael@skola.taby.se', 'user', '2026-05-06 13:19:50'),
(10, '9', 'scrypt:32768:8:1$ufS7NZOjNK6gSIEZ$e6af97d158767a570d9dd2a6259f86b66a62aaeac7bb8492028a58e07a923a71f931fe32ffae5da60b87c1ffeb39456296b773ff5e73c1c2c108761c14833c4d', 'axelk@skola.taby.se', 'user', '2026-05-06 13:21:33'),
(14, '10', 'scrypt:32768:8:1$Grd7iCORk2YFO2dC$d056f8b6ce017cf546979b1eca710150bfaecc638f18cef52b2c6f9d43a194de6900077c15c03bcd207632cb9dcb2548e5b448d94aadb9d3bdc99440e1a18170', 'akrantz@skola.taby.se', 'user', '2026-05-07 12:12:55'),
(15, '11', 'scrypt:32768:8:1$XcMqPaBt1Smg28qi$fad7c554d99c7a1ff4b8a1980b15b72b8b1c251a75444e25c38269c49b2d135a661fe117c8132d385054a6c3859d223e98854e77f9711d45025dff80c64254a1', 'axel.krantz@staby.se', 'user', '2026-05-07 12:13:12');

--
-- Index för dumpade tabeller
--

--
-- Index för tabell `posts`
--
ALTER TABLE `posts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `idx_posts_thread_created` (`thread_id`,`created_at`,`id`);

--
-- Index för tabell `threads`
--
ALTER TABLE `threads`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `idx_threads_pagination` (`created_at`,`id`),
  ADD KEY `idx_threads_last_post` (`last_post_at`,`id`),
  ADD KEY `idx_threads_last_post_id` (`last_post_id`);

--
-- Index för tabell `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_users_pagination` (`created_at`,`id`);

--
-- AUTO_INCREMENT för dumpade tabeller
--

--
-- AUTO_INCREMENT för tabell `posts`
--
ALTER TABLE `posts`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT för tabell `threads`
--
ALTER TABLE `threads`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT för tabell `users`
--
ALTER TABLE `users`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=16;

--
-- Restriktioner för dumpade tabeller
--

--
-- Restriktioner för tabell `posts`
--
ALTER TABLE `posts`
  ADD CONSTRAINT `posts_ibfk_1` FOREIGN KEY (`thread_id`) REFERENCES `threads` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `posts_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Restriktioner för tabell `threads`
--
ALTER TABLE `threads`
  ADD CONSTRAINT `threads_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL,
  ADD CONSTRAINT `threads_ibfk_2` FOREIGN KEY (`last_post_id`) REFERENCES `posts` (`id`) ON DELETE SET NULL;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
