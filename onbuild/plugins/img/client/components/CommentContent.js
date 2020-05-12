import React from 'react';
import PropTypes from 'prop-types';
import Img from 'react-image'


const IMAGE_REGEX = new RegExp(/(http(s?):)([/|.|\w|\s|-])*\.(?:jpg|gif|png|jpeg)/);

const CommentContent = ({ comment }) => {
  const images = [];

  // detect image links in comment
  comment.body.split('\n').forEach((line) => {
    line.split(' ').forEach((word) => {
      if (IMAGE_REGEX.test(word)) {
        images.push(word);
      }
    });
  });

  return (
    <div className="talk-plugin-img">
      <div className="talk-plugin-img-text">{ comment.body }</div>
      { images.length && (
        <div>
          <br />
          <Img
            src={ [images] }
            className="talk-plugin-img-image"
            style={{ maxHeight: '350px', maxWidth: '100%', height: 'auto' }}
          />
        </div>
      )}
    </div>
  );
};

CommentContent.propTypes = {
  comment: PropTypes.object.isRequired,
};

export default CommentContent;
