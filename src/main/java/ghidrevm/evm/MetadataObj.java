package ghidrevm.evm;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import org.bitcoinj.core.Base58;

public class MetadataObj {
	// Metadata Value
	private byte[] deployedByteCode;
	private byte[] metadataByteCode;
	private int startIndex;

	// Metadata Property
	private String ipfs;
	private String solcVersion;
	private Boolean experimental;
	private String bzzr0;
	private String bzzr1;
	private Map<String, Object> additionalFields;

	public MetadataObj(byte[] _deployedByteCode) {
		this.additionalFields = new HashMap<>();
		deployedByteCode = _deployedByteCode;
	}

	public byte[] getDeployedByteCode() {
		return deployedByteCode;
	}

	public byte[] getMetadataByteCode() {
		return metadataByteCode;
	}

	public int getStartIndex() {
		return startIndex;
	}

	public String getIpfs() {
		return ipfs;
	}

	private void setIpfs(String ipfs) {
		this.ipfs = ipfs;
	}

	public String getSolcVersion() {
		return solcVersion;
	}

	private void setSolcVersion(String solcVersion) {
		this.solcVersion = solcVersion;
	}

	public Boolean getExperimental() {
		return experimental;
	}

	private void setExperimental(Boolean experimental) {
		this.experimental = experimental;
	}

	public String getBzzr0() {
		return bzzr0;
	}

	private void setBzzr0(String bzzr0) {
		this.bzzr0 = bzzr0;
	}

	public String getBzzr1() {
		return bzzr1;
	}

	private void setBzzr1(String bzzr1) {
		this.bzzr1 = bzzr1;
	}

	public Map<String, Object> getAdditionalFields() {
		return additionalFields;
	}

	private void setAdditionalField(String key, Object value) {
		this.additionalFields.put(key, value);
	}
}
