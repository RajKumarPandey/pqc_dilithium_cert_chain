
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import datetime

# Import functions from the src directory
import sys
# Add the project root directory to sys.path to allow importing src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.cert_utils import create_placeholder_certificate, build_certificate_chain, generate_dilithium_keypair_placeholder


# Define the base project directory for tests (relative path for use within the test file)
# Note: When run via subprocess with cwd=BASE_DIR, this will resolve correctly.
BASE_DIR_RELATIVE = "."
SRC_DIR_RELATIVE = os.path.join(BASE_DIR_RELATIVE, "src")
TESTS_DIR_RELATIVE = os.path.join(BASE_DIR_RELATIVE, "tests")
DOCS_DIR_RELATIVE = os.path.join(BASE_DIR_RELATIVE, "docs")


# Define placeholder file paths used in previous steps (relative paths)
PLACEHOLDER_CERT_PATH = os.path.join(SRC_DIR_RELATIVE, "placeholder_certificate.pem")
PLACEHOLDER_PRIVATE_KEY_PATH = os.path.join(SRC_DIR_RELATIVE, "placeholder_private_key.pem")
PLACEHOLDER_ROOT_CERT_PATH = os.path.join(SRC_DIR_RELATIVE, "placeholder_root_certificate.pem")
PLACEHOLDER_INTERMEDIATE_CERT_PATH = os.path.join(SRC_DIR_RELATIVE, "placeholder_intermediate_certificate.pem")


class TestDilithiumCertChain(unittest.TestCase):

    def setUp(self):
        # Ensure the base directory and src directory exist before tests
        # These are relative to the cwd set by subprocess
        os.makedirs(SRC_DIR_RELATIVE, exist_ok=True)
        # Clean up any existing placeholder files from previous runs
        for f_path in [PLACEHOLDER_CERT_PATH, PLACEHOLDER_PRIVATE_KEY_PATH,
                       PLACEHOLDER_ROOT_CERT_PATH, PLACEHOLDER_INTERMEDIATE_CERT_PATH]:
            if os.path.exists(f_path):
                os.remove(f_path)

    def tearDown(self):
        # Clean up created placeholder files after tests
        for f_path in [PLACEHOLDER_CERT_PATH, PLACEHOLDER_PRIVATE_KEY_PATH,
                       PLACEHOLDER_ROOT_CERT_PATH, PLACEHOLDER_INTERMEDIATE_CERT_PATH]:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_project_structure_exists(self):
        # Test if the basic project structure was created (relative paths)
        self.assertTrue(os.path.exists(BASE_DIR_RELATIVE))
        self.assertTrue(os.path.exists(SRC_DIR_RELATIVE))
        self.assertTrue(os.path.exists(TESTS_DIR_RELATIVE))
        self.assertTrue(os.path.exists(DOCS_DIR_RELATIVE))
        self.assertTrue(os.path.exists(os.path.join(BASE_DIR_RELATIVE, "requirements.txt")))
        self.assertTrue(os.path.exists(os.path.join(BASE_DIR_RELATIVE, "README.md")))
        self.assertTrue(os.path.exists(os.path.join(BASE_DIR_RELATIVE, "LICENSE")))


    def test_certificate_creation_and_loading(self):
        # Test the certificate creation process using the placeholder function.

        # Generate a placeholder private key
        # In a real implementation, this would be a Dilithium private key.
        placeholder_private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )

        # Create a placeholder certificate
        certificate = create_placeholder_certificate(
            subject_name_str=u"mydomain.com",
            issuer_name_str=u"My Organization CA",
            private_key=placeholder_private_key
        )

        # Save the created certificate
        with open(PLACEHOLDER_CERT_PATH, "wb") as f:
            f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

        # Assert that the certificate file was created
        self.assertTrue(os.path.exists(PLACEHOLDER_CERT_PATH))

        # Test loading the certificate
        loaded_cert = None
        try:
            with open(PLACEHOLDER_CERT_PATH, "rb") as f:
                loaded_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        except Exception as e:
            self.fail(f"Failed to load created certificate: {e}")

        # Assert properties of the loaded certificate
        self.assertIsNotNone(loaded_cert)
        self.assertEqual(loaded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, u"mydomain.com")
        self.assertEqual(loaded_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, u"My Organization CA")
        self.assertTrue(loaded_cert.not_valid_before_utc <= datetime.datetime.utcnow())
        self.assertTrue(loaded_cert.not_valid_after_utc >= datetime.datetime.utcnow())
        self.assertIsNotNone(loaded_cert.public_key())

    def test_certificate_chain_building(self):
        # Test the certificate chain building process.
        # We need to ensure the leaf certificate file exists and optionally create placeholder
        # root and intermediate files with valid (even if minimal) PEM format for loading.

        # Generate placeholder keys for root, intermediate, and leaf
        root_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        intermediate_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        leaf_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())


        # Create placeholder certificates (Root, Intermediate, Leaf)
        # In a real chain, intermediate is signed by root, leaf by intermediate.
        # Here, for simplicity in testing the loading/chain building function,
        # we create independent placeholder certs.
        root_cert = create_placeholder_certificate(u"Root CA", u"Root CA", root_private_key)
        intermediate_cert = create_placeholder_certificate(u"Intermediate CA", u"Root CA", intermediate_private_key) # Issuer is Root CA placeholder
        leaf_cert = create_placeholder_certificate(u"leaf.com", u"Intermediate CA", leaf_private_key) # Issuer is Intermediate CA placeholder


        # Save the placeholder certificates to files
        with open(PLACEHOLDER_ROOT_CERT_PATH, "wb") as f:
             f.write(root_cert.public_bytes(encoding=serialization.Encoding.PEM))
        with open(PLACEHOLDER_INTERMEDIATE_CERT_PATH, "wb") as f:
             f.write(intermediate_cert.public_bytes(encoding=serialization.Encoding.PEM))
        with open(PLACEHOLDER_CERT_PATH, "wb") as f:
             f.write(leaf_cert.public_bytes(encoding=serialization.Encoding.PEM))

        # Now, attempt to load the certificates and build the chain using the function
        certificate_chain = build_certificate_chain(
            leaf_cert_path=PLACEHOLDER_CERT_PATH,
            intermediate_cert_paths=[PLACEHOLDER_INTERMEDIATE_CERT_PATH],
            root_cert_path=PLACEHOLDER_ROOT_CERT_PATH
        )

        # Assert properties of the built chain
        self.assertIsNotNone(certificate_chain)
        self.assertEqual(len(certificate_chain), 3, "Certificate chain should contain leaf, intermediate, and root.")
        self.assertEqual(certificate_chain[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, u"leaf.com")
        self.assertEqual(certificate_chain[1].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, u"Intermediate CA")
        self.assertEqual(certificate_chain[2].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, u"Root CA")

        # Test accessing certificates in the chain
        self.assertIsNotNone(certificate_chain[0])
        self.assertIsNotNone(certificate_chain[1])
        self.assertIsNotNone(certificate_chain[2])


# This allows running the tests directly when the script is executed
if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

