CREATE TABLE IF NOT EXISTS olt_terminal_mac_snapshot_batch (
  batch_id varchar(80) NOT NULL PRIMARY KEY,
  started_at datetime NOT NULL,
  finished_at datetime NULL,
  status enum('running','completed','partial','failed') NOT NULL,
  device_count int unsigned NOT NULL DEFAULT 0,
  success_device_count int unsigned NOT NULL DEFAULT 0,
  failed_device_count int unsigned NOT NULL DEFAULT 0,
  mapping_count bigint unsigned NOT NULL DEFAULT 0,
  scope_description varchar(255) NULL,
  error_summary text NULL,
  created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_finished (finished_at,status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS olt_onu_terminal_mac_snapshot (
  id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
  batch_id varchar(80) NOT NULL,
  collected_at datetime NOT NULL,
  olt_device_id int NOT NULL,
  olt_name varchar(100) NULL,
  vlan_id int NULL,
  if_index varchar(32) NULL,
  port_name varchar(100) NULL,
  onu_mac varchar(12) NOT NULL,
  terminal_mac varchar(12) NOT NULL,
  source_command varchar(255) NULL,
  created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_batch_path (batch_id,olt_device_id,vlan_id,port_name,onu_mac,terminal_mac),
  KEY idx_batch_terminal (batch_id,terminal_mac),
  KEY idx_batch_onu (batch_id,onu_mac),
  KEY idx_terminal_time (terminal_mac,collected_at),
  KEY idx_onu_time (onu_mac,collected_at),
  CONSTRAINT fk_terminal_snapshot_batch
    FOREIGN KEY (batch_id) REFERENCES olt_terminal_mac_snapshot_batch(batch_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
