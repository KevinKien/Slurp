//! Per-user storage, with permissions applied before secrets are written.
use anyhow::{bail, Context, Result};
use std::{fs::{self, OpenOptions}, io::Write, path::Path};

pub fn restrict(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.is_dir() != directory { bail!("Unsafe storage path: {}", path.display()); }
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(if directory {0o700} else {0o600}))?;
    }
    #[cfg(windows)] unsafe {
        use std::{ffi::c_void, os::windows::ffi::OsStrExt};
        #[link(name="advapi32")]
        extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text:*const u16, revision:u32, descriptor:*mut *mut c_void, size:*mut u32)->i32;
            fn SetFileSecurityW(path:*const u16, information:u32, descriptor:*mut c_void)->i32;
        }
        #[link(name="kernel32")]
        extern "system" { fn LocalFree(memory:*mut c_void)->*mut c_void; }
        // Protected DACL: only the file owner has access. Directories propagate it to children.
        let sddl:Vec<u16>=if directory {"D:P(A;OICI;FA;;;OW)"} else {"D:P(A;;FA;;;OW)"}.encode_utf16().chain(Some(0)).collect();
        let path_wide:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor=std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(),1,&mut descriptor,std::ptr::null_mut())==0 { return Err(std::io::Error::last_os_error().into()); }
        let result=SetFileSecurityW(path_wide.as_ptr(),0x80000004,descriptor);
        let error=std::io::Error::last_os_error(); LocalFree(descriptor);
        if result==0 {return Err(error.into());}
    }
    Ok(())
}

pub fn directory(path:&Path)->Result<()> {
    if !path.exists() {
        let mut builder=fs::DirBuilder::new();builder.recursive(true);
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt;builder.mode(0o700); }
        builder.create(path)?;
    }
    restrict(path,true)?;
    // Repair permissions on existing database sidecars, tokens, certificates and logs.
    for item in fs::read_dir(path)? {
        let item=item?;
        if !item.file_type()?.is_dir() { restrict(&item.path(),false)?; }
    }
    Ok(())
}

pub fn create(path:&Path, content:&[u8])->Result<()> {
    let mut options=OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt;options.mode(0o600); }
    let mut file=options.open(path).with_context(||format!("Cannot create {}",path.display()))?;
    restrict(path,false)?;
    file.write_all(content)?;file.sync_all()?;
    Ok(())
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn private_files_are_created_and_existing_modes_repaired() {
        let temp=tempfile::tempdir().unwrap();let dir=temp.path().join("data");directory(&dir).unwrap();
        let file=dir.join("secret");create(&file,b"test").unwrap();assert!(create(&file,b"overwrite").is_err());
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(&file,fs::Permissions::from_mode(0o644)).unwrap();directory(&dir).unwrap();assert_eq!(fs::metadata(dir).unwrap().permissions().mode()&0o777,0o700);assert_eq!(fs::metadata(file).unwrap().permissions().mode()&0o777,0o600);}
    }
    #[cfg(unix)] #[test] fn rejects_symlinks() {
        let temp=tempfile::tempdir().unwrap();let file=temp.path().join("real");fs::write(&file,"data").unwrap();let link=temp.path().join("link");std::os::unix::fs::symlink(file,&link).unwrap();assert!(restrict(&link,false).is_err());
    }
}
