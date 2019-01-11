use jsonrpc_core::Error;
use v1::types::{AddNodeOperation, NodeInfo};

/// Parity-bitcoin network interface
#[rpc]
pub trait Network {
	/// Add/remove/connect to the node
	/// @curl-example: curl --data-binary '{"jsonrpc": "2.0", "method": "addnode", "params": ["127.0.0.1:8888", "add"], "id":1 }' -H 'content-type: application/json' http://127.0.0.1:8332/
	/// @curl-example: curl --data-binary '{"jsonrpc": "2.0", "method": "addnode", "params": ["127.0.0.1:8888", "remove"], "id":1 }' -H 'content-type: application/json' http://127.0.0.1:8332/
	/// @curl-example: curl --data-binary '{"jsonrpc": "2.0", "method": "addnode", "params": ["127.0.0.1:8888", "onetry"], "id":1 }' -H 'content-type: application/json' http://127.0.0.1:8332/
	#[rpc(name = "addnode")]
	fn add_node(&self, String, AddNodeOperation) -> Result<(), Error>;
	/// Query node(s) info
	/// @curl-example: curl --data-binary '{"jsonrpc": "2.0", "id":"1", "method": "getaddednodeinfo", "params": [true] }' -H 'content-type: application/json' http://127.0.0.1:8332/
	/// @curl-example: curl --data-binary '{"jsonrpc": "2.0", "id":"1", "method": "getaddednodeinfo", "params": [true, "192.168.0.201"] }' -H 'content-type: application/json' http://127.0.0.1:8332/
	#[rpc(name = "getaddednodeinfo")]
	fn node_info(&self, bool, Option<String>) -> Result<Vec<NodeInfo>, Error>;
	/// Query node(s) info
	/// @curl-example: curl --data-binary '{"jsonrpc": "2.0", "id":"1", "method": "getconnectioncount", "params": [] }' -H 'content-type: application/json' http://127.0.0.1:8332/
	#[rpc(name = "getconnectioncount")]
	fn connection_count(&self) -> Result<usize, Error>;
}
