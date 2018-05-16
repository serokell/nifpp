// nix_store_nif.cc
// requires nix v2 and nifpp v3.
// copyright Serokell, AGPL 3.0
// see https://github.com/serokell/nix-cache/blob/master/COPYING

#include <nix/hash.hh>
#include <nix/local-store.hh>
#include <nix/nar-info.hh>
#include <nix/store-api.hh>
#include <nix/serialise.hh>

#include "../nifpp.hh"


struct PortSink : nix::BufferedSink {
  nifpp::Env env, msgenv;
  ErlNifPid destination;
  nifpp::TERM ref;
  PortSink(const ErlNifPid& pid, const nifpp::TERM& ref) :
    BufferedSink(),
    ref(env.copy(ref)), destination(pid) {}
  virtual void write(const unsigned char * data, size_t len) override {
    nifpp::binary result(len);
    // memcpy can probably be avoided by using enif_alloc_binary for buffer
    memcpy(result.data, data, len);
    this->send(nifpp::str_atom("data"), result);
  }
  template <typename ...Ts>
  inline void send(Ts&&... ts) {
    msgenv.send_and_clear(env, destination,
                          std::forward_as_tuple(nifpp::str_atom("nix_store"), msgenv.copy(ref), ts...));
  }
  virtual ~PortSink() override {
    assert(bufPos == 0);
  }
};

typedef nix::ref<const nix::ValidPathInfo> ValidPathRef;


class nix_store_nif {
  static nix::ref<nix::Store> getStore() {
    nix::settings.loadConfFile();
    nix::settings.lockCPU = false;
    return nix::openStore();
  }
  nix::ref<nix::Store> store;
  
  nix::ref<nix::LocalFSStore> ensure_local_store() {
    auto store_ref = store.dynamic_pointer_cast<nix::LocalFSStore>();
    if (!store_ref)
      throw nix::Error("you don't have sufficient rights to use this command");
    return nix::ref<nix::LocalFSStore>(store_ref);
  }

public:
  nix_store_nif(nifpp::Env env, nifpp::TERM info) : store(getStore()) {}
  nix_store_nif(const nix_store_nif&) = delete;
  nix_store_nif(nifpp::Env env, nix_store_nif& old, nifpp::TERM info);
  ~nix_store_nif() {}
  
  std::string get_real_store_dir() {
    return ensure_local_store()->getRealStoreDir();
  }
  
  std::string path_info_narinfo(ValidPathRef &pathref) {
    nix::NarInfo narInfo(*pathref);
    narInfo.compression = "none";
    narInfo.fileHash = narInfo.narHash;
    narInfo.fileSize = narInfo.narSize;
    narInfo.url = nix::storePathToHash(narInfo.path) + ".nar";
    
    return narInfo.to_string();
  }
  
  unsigned long path_info_narsize(ValidPathRef& pathref) {
    return pathref->narSize;
  }
  
  std::string query_path_from_hash_part(nix::Path &path) {
    return store->queryPathFromHashPart(path);
  }
  
  ValidPathRef query_path_info(nix::Path &path) {
    // TODO: async
    // caveat: caches wrong (prefix) lookups. use clearPathInfoCache to fix
    store->assertStorePath(path);
    return store->queryPathInfo(path);
  }
  
  ValidPathRef sign(ValidPathRef &pathref, std::string &key) {
    // doesn't save, don't need root
    nix::SecretKey secretKey(key);
    std::string signature = secretKey.signDetached(pathref->fingerprint());
    if (pathref->sigs.count(signature))
      return pathref;
    //return NULL; //nifpp::str_atom("duplicate");
    // copy as non-const
    auto info2 = nix::make_ref<nix::ValidPathInfo>(*pathref);
    info2->sigs.insert(signature);
    return info2;
  }

  nifpp::str_atom path_nar(nix::Path &path, ErlNifPid& pid, nifpp::TERM& ref) {
    auto sink = PortSink(pid, ref);
    try {
      store->narFromPath(path, sink);
      sink.flush();
      sink.send(nifpp::str_atom("end"));
    } catch (nix::Error & e) {
      sink.flush();
      sink.send(nifpp::str_atom("nix_error"), e.what());
    }
    return nifpp::str_atom("ok");
  }
  template<typename F> inline ERL_NIF_TERM handle_errors(nifpp::Env& env, const F&& f) {
    try { return f(); }
    catch (nix::InvalidPath) {
      return env.raise(nifpp::str_atom("nix_invalid_path"));
    }
    catch (nix::Error &e) {
      return env.raise((std::string)e.what());
    }
  }
};

const ErlNifEntry* nix_nif_entry() {
  typedef nix_store_nif n;
  static auto m = nifpp::module_<nix_store_nif>("nix_store_nif");
  return m
    .resource<ValidPathRef>("ValidPathInfo")
    .exports<&n::get_real_store_dir>("get_real_store_dir")
    .exports<&n::path_info_narinfo>("path_info_narinfo")
    .exports<&n::path_info_narsize>("path_info_narsize")
    .exports<&n::query_path_from_hash_part>("query_path_from_hash_part")
    .exports<&n::query_path_info>("query_path_info")
    .exports<&n::sign>("sign")
    .exports<&n::path_nar>("path_nar", nifpp::dirty::IO);
}
NIFPP_INIT(nix_nif_entry);


