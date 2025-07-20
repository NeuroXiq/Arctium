using System;

namespace Arctium.Standards.X509.X509Cert.Extensions
{
    /// <summary>
    /// Represents UserNotice structure of the X509 standard. This structure do 
    /// not include inner 'NoticeReference' structure, instead this inner struct is <br/>
    /// directly represented as a two fields <see cref="UserNotice.NoticeRefOrganization"/>
    /// and <see cref="NoticeRefNumbers"/>.
    /// If both options are included, notice ref should be displayed
    /// </summary>
    public class UserNotice
    {
        // NoticeRefOrganiz + NoteceRefNum represents extracted fields of 
        // structure defined in standard.
        // In this class shall be a next inner struct represents this both fields in this class,
        // something like: 
        //  struct NoticeReference
        //  {
        //    public string Oganization
        //    public byte[][] numbers
        //  }
        // but instead of this, im implemented this 2 fields directrly in this class.
        // 'NoticeRefernce' struct above is a optional and can be null
        // this means that when one filed is null, second one also must be null.
        // Fields also are NOT OPTIONAL and if one is present, 
        // second also must have a value (not null)


        /// <summary>
        /// Can be null (optional value). If this values is null, <see cref="NoticeRefNumbers"/> is also null <br/>
        /// </summary>
        public string NoticeRefOrganization { get; private set; }

        /// <summary>
        /// Can be null (optional value).If this values is null, <see cref="NoticeRefOrganization"/> is also null
        /// </summary>
        public byte[][] NoticeRefNumbers { get; private set; }

        /// <summary>
        /// Can be null (optional value) <br/>
        /// </summary>
        public string ExplicitText { get; private set; }

        /// <summary>
        /// Creates structure where all values are defined (all optional fields are present).
        /// </summary>
        /// <param name="noticeRefOrganization"></param>
        /// <param name="noticeRefNumbers"></param>
        /// <param name="explicitText"></param>
        public UserNotice(string noticeRefOrganization, byte[][] noticeRefNumbers, string explicitText)
        {
            if (noticeRefNumbers == null) throw new ArgumentNullException("noticeRefOrganization");
            if (noticeRefNumbers== null) throw new ArgumentNullException("noticeRefNumbers");
            if (explicitText == null) throw new ArgumentNullException("explicitText");

            NoticeRefNumbers = noticeRefNumbers;
            NoticeRefOrganization = noticeRefOrganization;
            ExplicitText = explicitText;
        }

        /// <summary>
        /// Creates structure where 'NoticeRef' optional field are present 
        /// (NoticeRefNumvers + NoticeRefOrganization) but <see cref="ExplicitText"/> is not.
        /// </summary>
        /// <param name="noticeRefOrganization"></param>
        public UserNotice(string noticeRefOrganization, byte[][] noticeRefNumbers)
        {
            if(noticeRefOrganization == null) throw new ArgumentNullException("noticeRefOrganization");
            if (noticeRefNumbers == null) throw new ArgumentNullException("noticeRefNumber");

            NoticeRefOrganization = noticeRefOrganization;
            NoticeRefNumbers = noticeRefNumbers;
        }

        public UserNotice(string explicitText)
        {
            ExplicitText = explicitText;
        }


        /// <summary>
        /// Represents structure where all OPTIONAL fields are not present
        /// </summary>
        public UserNotice()
        {
            NoticeRefNumbers = null;
            NoticeRefOrganization = null;
            ExplicitText = null;
        }

    }
}
