#![crate_name = "shred"]
/*
 * This file is part of the uutils coreutils package.
 *
 * (c) Michael Rosenberg <42micro@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */


/*
 TODO:
     * MAKE FASTER
     * Add recursive shredding
     * Add --iterations=X as a synonym for -n X
     * Add - for output to stdout
     * Use direct IO(?)
     * concurrency(?)
*/

extern crate getopts;
extern crate libc;

extern crate rand;
use rand::{ThreadRng, Rng};

use std::cell::{Cell, RefCell};
use std::env;
use std::fs;
use std::fs::File;
use std::io::Seek;
use std::io::{Write, BufWriter};
use std::fmt;
use std::fmt::Display;
use std::path;
use std::path::{Path, PathBuf};
use std::io;
use std::result::Result;
use std::error::Error;

#[path = "../common/util.rs"]
#[macro_use]
mod util;

static NAME: &'static str = "shred";
static VERSION_STR: &'static str = env!("CARGO_PKG_VERSION");
const DEFAULT_BLOCK_SIZE: usize = 4096;

// Allowed filename characters
const NAMESET: &'static str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.";

// Patterns as in the GNU coreutils shred implementation
const PATTERNS: [&'static [u8]; 22] = [
    b"\x00", b"\xFF",
    b"\x55", b"\xAA",
    b"\x24\x92\x49", b"\x49\x24\x92", b"\x6D\xB6\xDB", b"\x92\x49\x24",
        b"\xB6\xDB\x6D", b"\xDB\x6D\xB6",
    b"\x11", b"\x22", b"\x33", b"\x44", b"\x66", b"\x77", b"\x88", b"\x99", b"\xBB", b"\xCC",
        b"\xDD", b"\xEE",
];

#[derive(Clone, Copy)]
enum PassType<'a> {
    Pattern(&'a [u8]),
    Random,
}

enum ShredError {
    NameExhaustion,
    Unsupported(String),
    OpenErr(String),
    RemoveErr(String),
    StatErr(String),
    WriteErr(String),
    FsyncErr(String),
    SeekErr(String),
    RenameErr(String, String), // (rename_to, desc)
}

impl Display for ShredError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use ShredError::*;
        f.write_str(match *self {
            NameExhaustion               => "Exhausted nameset for renaming".to_string(),
            Unsupported(ref file_type)   => format!("Unsupported file type: {}", file_type),
            OpenErr(ref desc)            => format!("Couldn't open file: {}", desc),
            RemoveErr(ref desc)          => format!("Couldn't remove file: {}", desc),
            StatErr(ref desc)            => format!("Couldn't stat file: {}", desc),
            WriteErr(ref desc)           => format!("Couldn't write to file: {}", desc),
            FsyncErr(ref desc)           => format!("Couldn't fsync file: {}", desc),
            SeekErr(ref desc)            => format!("Couldn't seek file to 0: {}", desc),
            RenameErr(ref to, ref desc)  => format!("Couldn't rename to {}: {}", to, desc)
        }.as_ref())
    }
}

// Used for verbose and error output
struct ShredLogger {
    prog_name: String,
    filename: RefCell<String>,
    verbose: bool,
}

impl ShredLogger {
    fn new(prog_name: &str, verbose: bool) -> ShredLogger {
        ShredLogger { prog_name: prog_name.to_string(),
                      filename: RefCell::new(String::new()),
                      verbose: verbose }
    }

    fn set_filename(&mut self, filename: &str) {
        let mut f = self.filename.borrow_mut();
        f.clear();
        f.push_str(filename);
    }

    fn print_err<T: Display>(&self, err: T) {
        eprintln!("{}: {}", self.prog_name, err);
    }

    fn print_file_err<T: Display>(&self, err: T) {
        self.print_err(format!("{}: {}", *self.filename.borrow(), err));
    }

    fn print_file<T: Display>(&self, d: T) {
        println!("{}: {}: {}", self.prog_name, *self.filename.borrow(), d);
    }

    fn print_file_verbose<T: Display>(&self, d: T) {
        if self.verbose {
            self.print_file(d);
        }
    }

    fn print_shred_error(&self, err: ShredError) {
        self.print_file_err(format!("{}", err));
    }
}

trait FilenameStr {
    fn filename_str(&self) -> String;
}

trait ParentStr {
    fn parent_str(&self) -> String;
}

impl FilenameStr for path::Path {
    fn filename_str(&self) -> String {
        let s = match self.file_name() {
            Some(os_str) => os_str.to_str().unwrap_or(""),
            None => ""
        };

        s.to_string()
    }
}

impl ParentStr for path::Path {
    fn parent_str(&self) -> String {
        let s = match self.parent() {
            Some(path) => path.filename_str(),
            None => String::new() // Empty string
        };

        s
    }
}

// Output is encoded as lowercase hex
fn bytes_to_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    while s.len() < 6 {
        for byte in bytes.iter() {
            s.push_str(&format!("{:02x}", *byte));
            if s.len() == 6 { break; }
        }
    }

    s
}

// Used to generate all possible filenames of a certain length using NAMESET as an alphabet
struct FilenameGenerator {
    name_len: usize,
    nameset_indices: RefCell<Vec<usize>>, // Store the indices of the letters of our filename in NAMESET
    exhausted: Cell<bool>,
}

impl FilenameGenerator {
    fn new(name_len: usize) -> FilenameGenerator {
        let mut indices = Vec::new();
        for _ in 0..name_len {
            indices.push(0);
        }
        FilenameGenerator { name_len: name_len,
                            nameset_indices: RefCell::new(indices),
                            exhausted: Cell::new(false) }
    }
}

impl Iterator for FilenameGenerator {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.exhausted.get() {
            return None;
        }

        let mut nameset_indices = self.nameset_indices.borrow_mut();

        // Make the return value, then increment
        let mut ret = String::new();
        for i in nameset_indices.iter() {
            ret.push(NAMESET.chars().nth(*i).unwrap());
        }

        if nameset_indices[0] == NAMESET.len()-1 { self.exhausted.set(true) }
        // Now increment the least significant index
        for i in (0..self.name_len).rev() {
            if nameset_indices[i] == NAMESET.len()-1 {
                nameset_indices[i] = 0; // Carry the 1
                continue;
            }
            else {
                nameset_indices[i] += 1;
                break;
            }
        }

        Some(ret)
    }
}

// Used to generate blocks of bytes of size <= DEFAULT_BLOCK_SIZE based on either a give pattern
// or randomness
struct BytesGenerator<'a> {
    total_bytes: Option<u64>,
    bytes_generated: Cell<u64>,
    block_size: usize,
    exact: bool, // if false, every block's size is block_size
    gen_type: PassType<'a>,
    rng: Option<RefCell<ThreadRng>>,
}

impl<'a> BytesGenerator<'a> {
    // total_bytes is optional; if None is provided, this iterator will not terminate; a for loop
    // using this will only stop when it errors and returns
    fn new(total_bytes: Option<u64>, block_size: usize,
           gen_type: PassType<'a>, exact: bool) -> BytesGenerator {
        let rng = match gen_type {
            PassType::Random => Some(RefCell::new(rand::thread_rng())),
            _ => None,
        };

        BytesGenerator { total_bytes: total_bytes,
                         bytes_generated: Cell::new(0u64),
                         block_size: block_size,
                         exact: exact,
                         gen_type: gen_type,
                         rng: rng }
    }
}

impl<'a> Iterator for BytesGenerator<'a> {
    type Item = Box<[u8]>;

    fn next(&mut self) -> Option<Box<[u8]>> {
        // We go over the total_bytes limit when !self.exact and total_bytes isn't a multiple
        // of self.block_size
        if self.total_bytes.is_some() && self.bytes_generated.get() >= self.total_bytes.unwrap() {
            return None;
        }

        let this_block_size = {
            // If no total size is given, then this generator is an infinite stream
            if self.total_bytes.is_none() { self.block_size }
            else {
                let bytes_left = self.total_bytes.unwrap() - self.bytes_generated.get();
                if !self.exact { self.block_size }
                else if bytes_left >= self.block_size as u64 { self.block_size }
                else { (bytes_left % self.block_size as u64) as usize }
            }
        };

        let mut bytes : Vec<u8> = Vec::with_capacity(this_block_size);

        match self.gen_type {
            PassType::Random => {
                let mut rng = self.rng.as_ref().unwrap().borrow_mut();
                unsafe {
                    bytes.set_len(this_block_size);
                    rng.fill_bytes(&mut bytes);
                }
            }
            PassType::Pattern(pattern) => {
                let skip = {
                    if self.bytes_generated.get() == 0 { 0 }
                    else { (pattern.len() as u64 % self.bytes_generated.get()) as usize }
                };
                // Same range as 0..this_block_size but we start with the right index
                for i in skip..this_block_size+skip {
                    let index = i % pattern.len();
                    bytes.push(pattern[index]);
                }
            }
        };

        let new_bytes_generated = self.bytes_generated.get() + this_block_size as u64;
        self.bytes_generated.set(new_bytes_generated);
        Some(bytes.into_boxed_slice())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum FileType {
    RegFile,
    Dir,
    Symlink,
    BlockDev,
    CharDev,
    Tty,       // I know this isn't a separate file mode, but we distinguish TTYs because they are
               // not shreddable (they can't seek)
    Fifo,
    Socket,
    Unknown
}

impl Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use FileType::*;
        f.write_str(match *self {
            RegFile  => "Regular file",
            Dir      => "Directory",
            Symlink  => "Symlink",
            BlockDev => "Block device",
            CharDev  => "Character device",
            Tty      => "TTY",
            Fifo     => "FIFO",
            Socket   => "Socket",
            Unknown  => "Unknown"
        })
    }
}

struct ShredMetadata {
    file_type: FileType, // Not really necessary; size and block_size are enough
    size: u64,
    block_size: usize // Only really important for block devices
}

// We cannot handle char or block devices; error if it's one of those
#[cfg(not(unix))]
fn get_metadata(file: &File) -> Result<ShredMetadata, ShredError> {
    let fs_metadata = match file.metadata() {
        Err(e) => return Err(ShredError::StatErr(format!("{}", e))),
        Ok(m)  => m
    };
    let fs_file_type = fs_metadata.file_type();
    let file_type = match (fs_file_type.is_file(), fs_file_type.is_dir(), fs_file_type.is_symlink()) {
        (true, _, _) => FileType::RegFile,
        (_, true, _) => FileType::Dir,
        (_, _, true) => FileType::Symlink,
        (_, _, _)    => FileType::Unknown
    };
    if file_type != FileType::RegFile {
        return Err(ShredError::Unsupported(format!("{}", file_type)));
    }

    let size = fs_metadata.len() as u64;
    let block_size = DEFAULT_BLOCK_SIZE;

    Ok(ShredMetadata { file_type: file_type, size: size, block_size: block_size })
}

// We can handle block devices and non-tty char devices
#[cfg(unix)]
fn get_metadata(file: &File) -> Result<ShredMetadata, ShredError> {
    use libc::consts::os::posix88::*;
    use libc::funcs::posix88::unistd::isatty;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    let is_tty = unsafe { isatty(fd) };

    let fs_metadata = match file.metadata() {
        Err(e) => return Err(ShredError::StatErr(format!("{}", e))),
        Ok(m)  => m
    };
    let file_type = match fs_metadata.mode() & S_IFMT {
        S_IFREG  => FileType::RegFile,
        S_IFDIR  => FileType::Dir,
        S_IFLNK  => FileType::Symlink,
        S_IFBLK  => FileType::BlockDev,
        // I know this isn't a separate file mode, but we distinguish TTYs because they are not
        // shreddable (they can't seek)
        S_IFCHR  => if is_tty == 1 { FileType::Tty } else { FileType::CharDev },
        S_IFIFO  => FileType::Fifo,
        S_IFSOCK => FileType::Socket,
        _        => FileType::Unknown
    };
    // As in the original shred, error on unshreddable files: TTYs, FIFOs, and sockets
    match file_type {
        FileType::Tty  |
        FileType::Fifo |
        FileType::Socket => return Err(ShredError::Unsupported(format!("{}", file_type))),
        _                => ()
    }

    let size = fs_metadata.len() as u64;

    // Use the devices perferred block size if possible; if it's 0 then use the default
    let hw_block_size = fs_metadata.blksize() as usize;
    let block_size = if file_type == FileType::BlockDev && hw_block_size != 0 { hw_block_size }
                     else { DEFAULT_BLOCK_SIZE };

    Ok(ShredMetadata { file_type: file_type, size: size, block_size: block_size })
}


// Stolen and tweaked from ../du/du.rs by Joseph Crail. Thanks!
fn get_size(size_str_opt: Option<String>, logger: &ShredLogger) -> Option<u64> {
    if size_str_opt.is_none() { return None; }

    let size_str = size_str_opt.as_ref().unwrap();

    let num_str = size_str.chars().take_while(|c| c.is_digit(10)).collect::<String>();
    let suffix = size_str.chars().skip(num_str.len()).collect::<String>();

    let multiplier = match suffix.as_ref() {
        "" | "c" => 1,
        "w" => 2,
        "b" => 512,
        "kB" => 1000,
        "K" | "KiB" | "k" => 1024,
        "MB" => 1000 * 1000,
        "M" | "MiB" => 1024 * 1024,
        "GB" => 1000 * 1000 * 1000,
        "G" | "GiB" => 1024 * 1024 * 1024,
        "TB" => 1000 * 1000 * 1000 * 1000,
        "T" | "TiB" => 1024 * 1024 * 1024 * 1024,
        "PB" => 1000 * 1000 * 1000 * 1000 * 1000,
        "P" | "PiB" => 1024 * 1024 * 1024 * 1024 * 1024,
        "EB" => 1000 * 1000 * 1000 * 1000 * 1000 * 1000,
        "E" | "EiB" => 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
        _ => 0
    };

    let val = num_str.parse::<u64>().unwrap_or(0) * multiplier;
    if val == 0 {
        logger.print_err(&format!("{}: Invalid file size", &size_str));
        exit!(1);
    }

    Some(val)
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let prog_name: String = Path::new(&args[0]).filename_str();

    let mut opts = getopts::Options::new();
    opts.optopt("n", "iterations", "overwrite N times instead of the default (3)", "N");
    opts.optopt("s", "size", "shred this many bytes (suffixes like K, M, G accepted)", "FILESIZE");
    opts.optflag("u", "remove", "truncate and remove the file after overwriting; See below");
    opts.optflag("v", "verbose", "show progress");
    opts.optflag("x", "exact", "do not round file sizes up to the next full block;\
                                    this is the default for non-regular files");
    opts.optflag("z", "zero", "add a final overwrite with zeros to hide shredding");
    opts.optflag("", "help", "display this help and exit");
    opts.optflag("", "version", "output version information and exit");

    // Vec::tail() is unstable; use [1..] instead
    let matches = opts.parse(args[1..].iter()).unwrap_or_else(|e| {
        eprintln!("{}: {}", prog_name, e);
        exit!(1);
    });

    if matches.opt_present("help") {
        println!("Usage: {} [OPTION]... FILE...", prog_name);
        println!("Overwrite the specified FILE(s) repeatedly, in order to make it harder");
        print!("for even very expensive hardware probing to recover the data.");
        println!("{}", opts.usage(""));
        println!("Delete FILE(s) if --remove (-u) is specified.  The default is not to remove");
        println!("the files because it is common to operate on device files like /dev/hda,");
        println!("and those files usually should not be removed.");
        println!("");
        exit!(0);
    } else if matches.opt_present("version") {
        println!("{} {}", NAME, VERSION_STR);
        exit!(0);
    } else if matches.free.is_empty() {
        eprintln!("{}: Missing an argument", NAME);
        eprintln!("For help, try '{0} --help'", prog_name);
        exit!(0);
    } else {
        let iterations: usize = match matches.opt_str("iterations") {
            Some(s) => s.parse::<usize>().unwrap_or_else(|_| {
                           eprintln!("{}: Invalid number of passes", prog_name);
                           exit!(1);
                       }),
            None => 3
        };

        let verbose = matches.opt_present("verbose");

        let mut logger = ShredLogger::new(&prog_name, verbose);

        let remove = matches.opt_present("remove");
        let size = get_size(matches.opt_str("size"), &logger);
        let exact = matches.opt_present("exact") && size.is_none(); // if -s is given, ignore -x
        let zero = matches.opt_present("zero");

        for path_str in matches.free.into_iter() {
            let path = Path::new(&path_str);
            logger.set_filename(&path.filename_str());
            let _ = shred(path, iterations, remove, size, exact, zero, &logger).map_err(|se|
                logger.print_shred_error(se)
            );
        }
    }

    exit!(0);
}

fn shred(path: &Path, n_passes: usize, remove: bool,
         size: Option<u64>, exact: bool, zero: bool, logger: &ShredLogger) -> Result<(), ShredError> {

    try!(wipe_file(&path, n_passes, size, exact, zero, logger));

    if remove {
        logger.print_file("removing");
        let final_file_path = try!(wipe_name(&path, logger));
        try!(remove_file(&final_file_path));
        // path.filename_str() is the original filename (pre-wipe); use this when logging success
        logger.print_file_verbose("removed");
    }

    Ok(())
}

fn wipe_file(path: &Path, n_passes: usize, size: Option<u64>,
             exact: bool, zero: bool, logger: &ShredLogger) -> Result<(), ShredError> {

    let mut file = try!(fs::OpenOptions::new().write(true).open(&path).map_err(|e|
        ShredError::OpenErr(format!("{}", e)))
    );

    // Errors if the file type is not shreddable
    let metadata = try!(get_metadata(&file));

    // Fill up our pass sequence

    let mut pass_sequence: Vec<PassType> = Vec::new();

    // Exclusively use random passes if n_passes <= 3
    if n_passes <= 3 {
        for _ in 0..n_passes { pass_sequence.push(PassType::Random) }
    }
    // First fill it with Patterns, shuffle it, then evenly distribute Random
    else {
        let n_full_arrays = n_passes / PATTERNS.len(); // How many times can we go through all the patterns?
        let remainder = n_passes % PATTERNS.len(); // How many do we get through on our last time through?

        for _ in 0..n_full_arrays {
            for p in PATTERNS.iter() {
                pass_sequence.push(PassType::Pattern(*p));
            }
        }
        for i in 0..remainder {
            pass_sequence.push(PassType::Pattern(PATTERNS[i]));
        }
        rand::thread_rng().shuffle(&mut pass_sequence); // randomize the order of application

        let n_random: usize = 3 + n_passes/10; // Minimum 3 random passes; ratio of 10 after
        // Evenly space random passes; ensures one at the beginning and end
        for i in 0..n_random {
            pass_sequence[i * (n_passes - 1)/(n_random - 1)] = PassType::Random;
        }
    }

    // --zero specifies whether we want one final pass of 0x00 on our file
    if zero { pass_sequence.push(PassType::Pattern(b"\x00")); }
    let total_passes = n_passes + { if zero { 1 } else { 0 } }; // shorthand here would be confusing

    for (i, pass_type) in pass_sequence.iter().enumerate() {
        // Set up the string that will be printed to the console in vebose mode
        let mut log_str = {
            if total_passes < 10 {
                format!("pass {}/{} ", i+1, total_passes)
            } else {
                format!("pass {:2.0}/{:2.0} ", i+1, total_passes)
            }
        };
        log_str.push_str(match *pass_type {
            PassType::Random => "(random)".to_string(),
            PassType::Pattern(p) => format!("({})", bytes_to_string(p))
        }.as_ref());

        logger.print_file_verbose(&log_str);

        // size is an optional argument for exactly how many bytes we want to shred
        // Do not fail if writes, stats, or syncs fail; just notify the user and keep going
        let _ = do_pass(&mut file, &metadata, *pass_type, size, exact).map_err(|se|
            logger.print_shred_error(se)
        );

        // Sync data & metadata to disk after each pass just in case
        let _ = file.sync_all().map_err(|e| {
            let se = ShredError::FsyncErr(format!("{}", e));
            logger.print_shred_error(se);
        });

        // Failing to seek is a fatal error; if we cannot seek, we cannot do more than 1 pass
        match file.seek(io::SeekFrom::Start(0)) {
            Err(e) => return Err(ShredError::SeekErr(format!("{}", e))),
            _ => ()
        }
    }

    Ok(())
}

fn do_pass(file: &mut fs::File, metadata: &ShredMetadata, generator_type: PassType,
           given_file_size: Option<u64>, exact: bool) -> Result<(), ShredError> {

    // How many bytes are going to be used to do one pass on this file; recall --size
    // specifies how many bytes we want to shred; if not provided, use the file size
    // from the file's metadata
    let effective_file_size = match given_file_size {
        Some(given) => given,
        None => metadata.size
    };
    let generator = match effective_file_size {
        // No limit; write until an error occurs
        0 => BytesGenerator::new(None, metadata.block_size, generator_type, exact),
        // Normal stream
        _ => BytesGenerator::new(Some(effective_file_size), metadata.block_size, generator_type, exact),
    };

    let mut buf_writer = BufWriter::new(file);

    for block in generator {
        try! {
            buf_writer.write_all(&*block)
                      .map_err(|e| ShredError::WriteErr(format!("{}", e)))
        }
    }

    Ok(())
}

// Repeatedly renames the file with strings of decreasing length (most likely all 0s)
// Return the path of the file after its last renaming or None if error
fn wipe_name(file_path: &Path, logger: &ShredLogger) -> Result<PathBuf, ShredError> {
    let basename_len: usize = file_path.filename_str().len();
    let dir_path = match file_path.parent() {
        Some(p) => if p.as_os_str().to_string_lossy().len() == 0 {
                      Path::new(".") // If it's "" then it's the current dir
                   }
                   else { p },
        None => Path::new("/")
    };

    // make a fs::File for the containing directory so we can call fsync() after every rename
    let dir_file = try!(fs::OpenOptions::new().read(true).open(&dir_path)
                            .map_err(|e| ShredError::OpenErr(format!("{}", e)))
                       );

    let mut last_path = file_path.to_path_buf();

    for length in (1..basename_len+1).rev() {
        match name_pass(length, &last_path, dir_path) {
            Ok(new_path) => {
                logger.print_file_verbose(&format!("renamed to {}", new_path.filename_str()));
                last_path = new_path;
            },
            Err(se) => logger.print_shred_error(se),
        }
        // Sync this change to disk immediately; Note: this is equivalent to the
        // --remove=wipesync option in coreutils' shred. Here, it is the only option
        let _ = dir_file.sync_all().map_err(|e| {
            let se = ShredError::FsyncErr(format!("{}", e));
            logger.print_shred_error(se);
        });
    }

    Ok(last_path)
}

fn name_pass(new_name_len: usize, file_path: &Path, dir_path: &Path) -> Result<PathBuf, ShredError> {
    for name in FilenameGenerator::new(new_name_len) {
        let new_path = dir_path.join(&name);

        // Check if the new path already exists. If it's already
        // taken, move along
        if fs::metadata(&new_path).is_ok() { continue }

        match fs::rename(&file_path, &new_path) {
            Ok(_) => return Ok(new_path),
            Err(e) => return Err(ShredError::RenameErr(new_path.filename_str(),
                                                       format!("{}", e)))
        }
    } // If every possible filename already exists, just reduce the length and try again

    Err(ShredError::NameExhaustion)
}

fn remove_file(path: &Path) -> Result<(), ShredError> {
    fs::remove_file(path)
        .map(|_| ())
        .map_err(|e| ShredError::RemoveErr(format!("{}", e)))
}
