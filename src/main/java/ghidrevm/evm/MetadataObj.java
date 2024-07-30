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

	public void decodeMetadata() throws IOException {
		byte[] metadataByteCode = getMetadataByteCode(this.deployedByteCode);
		if (metadataByteCode == null)
			return;

		JsonNode metadataJsonNode = decodeCborToJsonNode(metadataByteCode);

		metadataJsonNode.fields().forEachRemaining(entry -> {
			String fieldName = entry.getKey();
			JsonNode fieldValue = entry.getValue();

			switch (fieldName) {
				case "solc":
					String version = extractVersion(extractHexString(fieldValue, ""));
					this.setSolcVersion(version);
					break;
				case "ipfs":
					this.setIpfs(extractIpfsHash(fieldValue, ""));
					break;
				case "experimental":
					this.setExperimental(fieldValue.asBoolean());
					break;
				case "bzzr0":
					this.setBzzr0(extractHexString(fieldValue, ""));
					break;
				case "bzzr1":
					this.setBzzr1(extractHexString(fieldValue, ""));
					break;
				default:
					this.setAdditionalField(fieldName, extractHexString(fieldValue, null));
					break;
			}

		});
	}

	private byte[] getMetadataByteCode(byte[] data) {
		int bytesLength = 2;

		// Can not decode metadata length
		if (data.length < bytesLength)
			return null;

		int metadataLength = ((data[data.length - 2] & 0xFF) << 8) | (data[data.length - 1] & 0xFF);

		// Metadata length not matched
		if (data.length - bytesLength - metadataLength <= 0)
			return null;

		// Extract metadata section
		byte[] metadata = new byte[metadataLength];
		this.startIndex = data.length - metadataLength - 2;
		System.arraycopy(data, data.length - metadataLength - 2, metadata, 0, metadata.length);

		this.metadataByteCode = metadata;

		return metadata;
	}

	private static JsonNode decodeCborToJsonNode(byte[] cborData) throws IOException {
		CBORFactory cborFactory = new CBORFactory();
		ObjectMapper cborMapper = new ObjectMapper(cborFactory);
		return cborMapper.readTree(cborData);
	}

	private static String extractHexString(JsonNode data, String defaultValue) {
		try {
			return jsonNodeToHex(data);
		} catch (IOException e) {
			e.printStackTrace();
			return defaultValue;
		}
	}

	private static String extractVersion(String version) {
		if (version.length() < 8)
			return "";

		version = version.substring(2);

		String data = "";
		int decimalString = 0;
		decimalString = Integer.parseInt(version.substring(0, 2));
		data += decimalString + ".";

		decimalString = Integer.parseInt(version.substring(2, 4));
		data += decimalString + ".";

		decimalString = Integer.parseInt(version.substring(4, 6));
		data += decimalString;

		return data;
	}

	private static String extractIpfsHash(JsonNode fieldValue, String defaultValue) {
		try {
			byte[] _base58EncodedHash = jsonNodeToByte(fieldValue);
			byte[] base58EncodedHash = new byte[_base58EncodedHash.length - 2];
			System.arraycopy(_base58EncodedHash, 2, base58EncodedHash, 0, base58EncodedHash.length);
			return Base58.encode(base58EncodedHash);
		} catch (IOException e) {
			e.printStackTrace();
			return defaultValue;
		}
	}

	private static String jsonNodeToHex(JsonNode jsonNode) throws IOException {
		byte[] cborBytes = jsonNodeToByte(jsonNode);

		// Convert byte array to hexadecimal string
		StringBuilder hexString = new StringBuilder();
		for (byte b : cborBytes) {
			String hex = String.format("%02X", b & 0xFF); // Convert byte to unsigned hex string
			hexString.append(hex);
		}

		return hexString.toString();
	}

	private static byte[] jsonNodeToByte(JsonNode jsonNode) throws IOException {
		// Create a CBOR factory and object mapper
		CBORFactory cborFactory = new CBORFactory();
		ObjectMapper cborMapper = new ObjectMapper(cborFactory);

		// Convert JsonNode to CBOR-encoded byte array
		byte[] cborBytes = cborMapper.writeValueAsBytes(jsonNode);
		return cborBytes;
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
