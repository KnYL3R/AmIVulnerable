namespace Modells {

    /// <summary>
    /// Object, that include only 2 Values and is designed for the test-database.
    /// </summary>
    public class TestIdValueObject {

        /// <summary>ID in the Database</summary>
        /// <value>Integer, that hold the ID.</value>
        public int Id { get; set; }
        /// <summary>Value, that is presented in the ID.</summary>
        /// <value>Current Value.</value>
        public int Value { get; set; }
    }
}
