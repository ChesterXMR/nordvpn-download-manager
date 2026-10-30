#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod browser;
mod commands;
mod engine;
mod nord;
mod recommend;
mod settings;
mod sites;
mod util;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let manager = engine::DownloadManager::load(app.handle().clone())?;
            app.manage(manager);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_settings,
            commands::save_settings,
            commands::sign_in,
            commands::sign_in_with_token,
            commands::sign_out,
            commands::open_nord_account,
            commands::save_gofile_token,
            commands::list_countries,
            commands::system_recommendation,
            commands::add_download,
            commands::list_downloads,
            commands::pause_download,
            commands::resume_download,
            commands::remove_download,
            commands::open_download,
            commands::reveal_download,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Nord Download Manager");
}
