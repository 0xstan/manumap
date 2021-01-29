class manumap
{
    // Those patterns are used to populate the loader with values generated
    // at runtime. Those values are used by the functions build_offset to find
    // the offsets of thoses patterns in the loader.

    // Those ones are replaced at runtime with the value of ecx/rcx before 
    // the thread hijacking
    const long pattern_ecx_32 = 0x42424242;
    const long long pattern_ecx_64 = 0x4242424242424242;
    
    // Those ones are replaced at runtime with the value of eip/rip before 
    // the thread hijacking
    const long pattern_eip_32 = 0x41414141;
    const long long pattern_eip_64 = 0x4141414141414141;

    // Thoses ones are replaced at runtime with the address of our dll.
    const long pattern_ecx_alloc_32 = 0x43434343;
    const long long pattern_ecx_alloc_64 = 0x4343434343434343;


    public:
        // Constructor
        manumap( char*, char* );

        // This method is the only one to call to inject in the dll.
        void inject( void );

    private:
        // Pid of the target process
        long pid;
        // Random thread in this process
        long tid;
        // Architecture of the dll we want to inject. Obviously this need to 
        // match the architecture of the target process.
        bool is_64;

        // Path of the injected file
        std::experimental::filesystem::path path;
        // Content of the file which will be written in the targeted process.
        std::vector<uint8_t> c;
        // Address of the file in the targeted process
        void* alloc;

        // Address of the loader in the targeted process
        void* loader;
        // Loader size, as there's a 32 and a 64 bits loader.
        long loader_sz;

        // Thoses are the vectors containing the offsets of the DWORD/QWORD
        // to replace in the loader.
        std::vector<long> offset_orig_rcx;
        std::vector<long> offset_orig_rip;
        std::vector<long> offset_alloc_rcx;

        // Find the process corresponding to the pid. This one is here to 
        // assert that the pid exists
        void find_processes( void );
        // Find file on disk
        void find_file( void );
        // Alloc memory in the targeted process ( for both loader and binary )
        void alloc_in_target( void );
        // Map Loader in target
        void map_loader( void );
        // Map file in target. Each sections is written at it s own virtual
        // address.
        void map_file( void );
        // Find a thread in the target. It'll be used for thread hijacking
        void find_thread_in_target( void );
        // Those two methods hijack a thread of the target and make the loader 
        // run. The loader perform relocations, build IAT, call TlsCallbacks
        // and run EntryPoint.
        void launch_loader32( void );
        void launch_loader64( void );
        // Build the vector of offsets to be replaced at runtime
        void build_offset32( void*, long);
        void build_offset64( void*, long);
};
